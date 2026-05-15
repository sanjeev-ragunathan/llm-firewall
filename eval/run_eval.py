"""
eval/run_eval.py
----------------
Runs an evaluation suite against the CheesyWasp firewall HTTP API.

UPDATED: now captures the LLM's actual response text so a post-hoc refusal
judge can determine which "allowed" requests were actually refused by the
underlying model (true ASR) vs. complied with (real attack success).

Usage:
    python -m eval.run_eval --output eval/results/full.csv
    python -m eval.run_eval --output eval/results/no_firewall.csv
    python -m eval.run_eval --output eval/results/full.csv \\
        --n-advbench 50 --n-dolly 150     # reduced suite
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path
from typing import List, Optional

import requests
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval.datasets import (  # noqa: E402
    EvalPrompt,
    load_advbench,
    load_dolly_benign,
    load_jailbreakbench,
)


CSV_HEADER = [
    "source",
    "label",
    "behavior",
    "prompt",
    "allowed",
    "blocked_by",
    "blocked_layer",
    "threat_type",
    "llm_response",        # NEW: actual model output for refusal judging
    "prompt_inspect_ms",
    "llm_ms",
    "response_inspect_ms",
    "total_ms",
    "client_total_ms",
    "error",
]


def run_prompt(
    endpoint: str,
    prompt: str,
    extra_params: Optional[dict] = None,
    timeout: float = 120.0,
) -> dict:
    payload = {"prompt": prompt}
    if extra_params:
        payload.update(extra_params)
    t0 = time.perf_counter()
    try:
        r = requests.post(endpoint, json=payload, timeout=timeout)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        if r.status_code != 200:
            return {
                "error": f"HTTP {r.status_code}: {r.text[:200]}",
                "_client_elapsed_ms": elapsed_ms,
            }
        data = r.json()
        data["_client_elapsed_ms"] = elapsed_ms
        return data
    except Exception as e:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        return {"error": f"{type(e).__name__}: {e}", "_client_elapsed_ms": elapsed_ms}


def row_for(prompt: EvalPrompt, resp: dict) -> list:
    meta = (resp.get("metadata") or {}).get("latency") or {}
    # The firewall response stores the user-facing string in `response`,
    # and the raw pre-redaction string in metadata.raw_llm_response.
    # We capture the raw one so the refusal judge sees what the model
    # actually generated, not the redacted version.
    full_meta = resp.get("metadata") or {}
    llm_response = full_meta.get("raw_llm_response") or resp.get("response") or ""
    # Truncate to keep CSV manageable — refusal judge only needs the prefix
    if llm_response:
        llm_response = llm_response[:500].replace("\n", " ").replace("\r", " ")
    return [
        prompt.source,
        prompt.label,
        prompt.behavior,
        prompt.text,
        resp.get("allowed", ""),
        resp.get("blocked_by", ""),
        resp.get("blocked_layer", ""),
        resp.get("threat_type", ""),
        llm_response,
        meta.get("prompt_inspection_ms", ""),
        meta.get("llm_latency_ms", ""),
        meta.get("response_inspection_ms", ""),
        meta.get("total_ms", ""),
        resp.get("_client_elapsed_ms", ""),
        resp.get("error", ""),
    ]


def evaluate(
    endpoint: str,
    prompts: List[EvalPrompt],
    output_path: Path,
    extra_params: Optional[dict] = None,
    write_every: int = 10,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADER)
        for i, p in enumerate(tqdm(prompts, desc=f"-> {output_path.name}")):
            resp = run_prompt(endpoint, p.text, extra_params=extra_params)
            writer.writerow(row_for(p, resp))
            if i % write_every == 0:
                f.flush()


def parse_extra_params(items: List[str]) -> dict:
    out = {}
    for item in items or []:
        if "=" not in item:
            raise SystemExit(f"--extra-param must be key=value, got: {item!r}")
        k, v = item.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", default="http://localhost:8000/v1/chat")
    ap.add_argument("--output", required=True)
    ap.add_argument("--datasets", nargs="+",
                    choices=["jbb", "advbench", "dolly"],
                    default=["jbb", "advbench", "dolly"])
    ap.add_argument("--n-advbench", type=int, default=100)
    ap.add_argument("--n-dolly", type=int, default=500)
    ap.add_argument("--extra-param", action="append", default=[])
    args = ap.parse_args()

    prompts: List[EvalPrompt] = []
    if "jbb" in args.datasets:
        prompts += load_jailbreakbench()
    if "advbench" in args.datasets:
        prompts += load_advbench(n=args.n_advbench)
    if "dolly" in args.datasets:
        prompts += load_dolly_benign(n=args.n_dolly)

    print(f"Loaded {len(prompts)} prompts -> {args.endpoint}")
    extra = parse_extra_params(args.extra_param)
    evaluate(args.endpoint, prompts, Path(args.output), extra_params=extra)
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()