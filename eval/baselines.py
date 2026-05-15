"""
eval/baselines.py
-----------------
Baseline comparison: run the same evaluation prompts through Llama Guard 3
(Meta's open safety classifier) and Prompt Guard 2, then write CSVs in the
same schema as run_eval.py so charts.py can compare directly.

Models:
- meta-llama/Llama-Guard-3-1B  - chat-template safety classifier (1B params).
  Reference: Inan et al. 2023, "Llama Guard: LLM-based Input-Output Safeguard
  for Human-AI Conversations", arXiv:2312.06674.
- meta-llama/Llama-Prompt-Guard-2-86M - lightweight prompt-injection
  classifier from the same family (~86M, DeBERTa-based).

Both require a HuggingFace account with access granted (the Llama license is
a gated download). Run `huggingface-cli login` and accept terms on the model
pages.

Run:
    python -m eval.baselines --model llama-guard --output eval/results/llamaguard.csv
    python -m eval.baselines --model prompt-guard --output eval/results/promptguard.csv
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path
from typing import List

from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval.datasets import (  # noqa: E402
    EvalPrompt,
    load_advbench,
    load_dolly_benign,
    load_jailbreakbench,
)


# ---------------------------------------------------------------------------
# Llama Guard 3 (1B) - chat template, generates "safe"/"unsafe"
# ---------------------------------------------------------------------------
class LlamaGuardAdapter:
    model_id = "meta-llama/Llama-Guard-3-1B"

    def __init__(self, device: str = None):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self.torch = torch
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        print(f"[llama-guard] Loading {self.model_id} on {self.device}...")
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_id)
        self.model = AutoModelForCausalLM.from_pretrained(
            self.model_id,
            torch_dtype=torch.bfloat16 if self.device == "cuda" else torch.float32,
        ).to(self.device)
        self.model.eval()

    def check(self, prompt: str) -> dict:
        chat = [{"role": "user", "content": prompt}]
        input_ids = self.tokenizer.apply_chat_template(
            chat, return_tensors="pt"
        ).to(self.device)
        t0 = time.perf_counter()
        with self.torch.no_grad():
            output = self.model.generate(
                input_ids=input_ids,
                max_new_tokens=20,
                pad_token_id=self.tokenizer.eos_token_id,
                do_sample=False,
            )
        latency_ms = (time.perf_counter() - t0) * 1000
        generated = self.tokenizer.decode(
            output[0][input_ids.shape[-1]:], skip_special_tokens=True
        ).strip()
        is_unsafe = generated.lower().startswith("unsafe")
        return {
            "allowed": not is_unsafe,
            "verdict": generated,
            "latency_ms": latency_ms,
        }


# ---------------------------------------------------------------------------
# Prompt Guard 2 (86M) - DeBERTa, binary injection classifier
# ---------------------------------------------------------------------------
class PromptGuardAdapter:
    model_id = "meta-llama/Llama-Prompt-Guard-2-86M"

    def __init__(self, device: str = None, threshold: float = 0.5):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.torch = torch
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.threshold = threshold
        print(f"[prompt-guard] Loading {self.model_id} on {self.device}...")
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_id)
        self.model = AutoModelForSequenceClassification.from_pretrained(self.model_id)
        self.model.to(self.device).eval()

    def check(self, prompt: str) -> dict:
        inputs = self.tokenizer(
            prompt, return_tensors="pt", truncation=True, max_length=512
        ).to(self.device)
        t0 = time.perf_counter()
        with self.torch.no_grad():
            logits = self.model(**inputs).logits
        latency_ms = (time.perf_counter() - t0) * 1000
        probs = self.torch.softmax(logits, dim=-1)[0].cpu().tolist()
        # class 1 = injection in PromptGuard family
        injection_prob = probs[1] if len(probs) > 1 else probs[0]
        is_attack = injection_prob >= self.threshold
        return {
            "allowed": not is_attack,
            "verdict": f"injection_prob={injection_prob:.3f}",
            "latency_ms": latency_ms,
        }


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
ADAPTERS = {
    "llama-guard": LlamaGuardAdapter,
    "prompt-guard": PromptGuardAdapter,
}


def evaluate(adapter, prompts: List[EvalPrompt], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        # Match run_eval CSV schema so charts.py works uniformly
        w.writerow(
            [
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
        )
        for p in tqdm(prompts, desc=f"-> {output_path.name}"):
            try:
                r = adapter.check(p.text)
                w.writerow(
                    [
                        p.source,
                        p.label,
                        p.behavior,
                        p.text,
                        r["allowed"],
                        "BASELINE" if not r["allowed"] else "",
                        type(adapter).__name__,
                        "BASELINE" if not r["allowed"] else "",
                        "",
                        "",
                        "",
                        r["latency_ms"],
                        r["latency_ms"],
                        "",
                    ]
                )
            except Exception as e:
                w.writerow(
                    [
                        p.source,
                        p.label,
                        p.behavior,
                        p.text,
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        f"{type(e).__name__}: {e}",
                    ]
                )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=list(ADAPTERS.keys()), required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--n-advbench", type=int, default=100)
    ap.add_argument("--n-dolly", type=int, default=500)
    args = ap.parse_args()

    prompts = (
        load_jailbreakbench()
        + load_advbench(n=args.n_advbench)
        + load_dolly_benign(n=args.n_dolly)
    )
    print(f"Loaded {len(prompts)} prompts; running {args.model} baseline")
    adapter = ADAPTERS[args.model]()
    evaluate(adapter, prompts, Path(args.output))
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
