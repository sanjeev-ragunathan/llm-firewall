"""
eval/run_eval.py
----------------
Runs an evaluation suite against the CheesyWasp firewall HTTP API.

Records, per-prompt:
    - dataset source + ground-truth label (harmful/benign)
    - firewall decision (allowed / blocked, layer, threat type)
    - per-layer + total latency (server-side, from the firewall's audit trail)
    - client-side wall-clock (for sanity check)

The firewall is expected to accept different *modes* (e.g. no firewall, L1
only, full pipeline) via either an env var read at server boot or a query
parameter. This script does NOT swap modes itself - run it once per
configuration with a separately-launched server (or pass --mode-query-param).

Usage:
    python -m eval.run_eval --output eval/results/full.csv
    python -m eval.run_eval --output eval/results/l1_only.csv \\
        --extra-param config=l1_only
    python -m eval.run_eval --output eval/results/no_firewall.csv \\
        --extra-param config=none

Tip: start the server with FIREWALL_MODE={none|l1|full} and re-run this
script with the matching --output name. The mode itself is NOT inferred from
the CSV.
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

# Make this script runnable both as `python -m eval.run_eval` and `python eval/run_eval.py`
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
    """Send a single prompt to the firewall endpoint and return its JSON dict."""
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
    """Flatten a firewall response into the CSV row schema."""
    meta = (resp.get("metadata") or {}).get("latency") or {}
    return [
        prompt.source,
        prompt.label,
        prompt.behavior,
        prompt.text,
        resp.get("allowed", ""),
        resp.get("blocked_by", ""),
        resp.get("blocked_layer", ""),
        resp.get("threat_type", ""),
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
    ap.add_argument(
        "--endpoint",
        default="http://localhost:8000/v1/chat",
        help="Firewall HTTP endpoint",
    )
    ap.add_argument(
        "--output",
        required=True,
        help="Output CSV path. Name it to match the config (e.g. full.csv).",
    )
    ap.add_argument(
        "--datasets",
        nargs="+",
        choices=["jbb", "advbench", "dolly"],
        default=["jbb", "advbench", "dolly"],
        help="Which datasets to include.",
    )
    ap.add_argument("--n-advbench", type=int, default=100)
    ap.add_argument("--n-dolly", type=int, default=500)
    ap.add_argument(
        "--extra-param",
        action="append",
        default=[],
        help="Additional JSON fields, e.g. --extra-param config=full",
    )
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
