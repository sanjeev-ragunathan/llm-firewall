"""
eval/datasets.py
----------------
Loaders for prompt-injection / jailbreak evaluation benchmarks.

Datasets:
- JailbreakBench (JBB-Behaviors) - Chao et al. 2024, arXiv:2404.01318
    100 harmful + 100 benign behaviors aligned to OpenAI usage policies.
    HF: JailbreakBench/JBB-Behaviors (open, MIT).
- AdvBench - Zou et al. 2023, arXiv:2307.15043
    520 direct harmful instructions used as the seed for GCG.
    HF: walledai/AdvBench (gated). Fallback: original llm-attacks CSV on GitHub.
- Dolly-15k - Databricks 2023
    Benign instruction-tuning dataset; used here to measure false positive rate
    (over-defense per InjecGuard, Li et al. 2024, arXiv:2410.22770).
    HF: databricks/databricks-dolly-15k (open, CC-BY-SA 3.0).

Each loader returns a list of EvalPrompt dataclasses with a stable schema so
the eval driver can treat all datasets uniformly.
"""

from __future__ import annotations

import csv
import io
import random
import urllib.request
from dataclasses import dataclass
from typing import List, Literal


ADVBENCH_FALLBACK_URL = (
    "https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/"
    "data/advbench/harmful_behaviors.csv"
)


@dataclass
class EvalPrompt:
    text: str
    label: Literal["harmful", "benign"]
    source: str
    behavior: str = ""  # category / behavior name if available


# ---------------------------------------------------------------------------
# JailbreakBench
# ---------------------------------------------------------------------------
def load_jailbreakbench() -> List[EvalPrompt]:
    """
    Loads the JBB-Behaviors dataset (100 harmful + 100 benign).
    HuggingFace: JailbreakBench/JBB-Behaviors, config 'behaviors'.
    Schema: Behavior, Goal, Target, Category, Source.
    """
    from datasets import load_dataset

    ds = load_dataset("JailbreakBench/JBB-Behaviors", "behaviors")

    out: List[EvalPrompt] = []
    for split, label in (("harmful", "harmful"), ("benign", "benign")):
        if split not in ds:
            continue
        for row in ds[split]:
            out.append(
                EvalPrompt(
                    text=row.get("Goal") or row.get("goal") or "",
                    label=label,
                    source="JailbreakBench",
                    behavior=row.get("Category", row.get("category", "")),
                )
            )
    return [p for p in out if p.text.strip()]


# ---------------------------------------------------------------------------
# AdvBench
# ---------------------------------------------------------------------------
def load_advbench(n: int = 100, seed: int = 42) -> List[EvalPrompt]:
    """
    Loads a sample of AdvBench harmful behaviors.
    Tries HF (walledai/AdvBench) first; falls back to the original llm-attacks
    CSV on GitHub if HF requires auth or is unavailable.
    """
    rows = _load_advbench_hf() or _load_advbench_github()
    if rows is None:
        raise RuntimeError(
            "Could not load AdvBench from HF or GitHub. "
            "If HF requires auth, run `huggingface-cli login` and accept "
            "the terms at https://huggingface.co/datasets/walledai/AdvBench"
        )
    random.Random(seed).shuffle(rows)
    rows = rows[:n]
    return [
        EvalPrompt(text=r, label="harmful", source="AdvBench")
        for r in rows
        if r.strip()
    ]


def _load_advbench_hf():
    try:
        from datasets import load_dataset

        ds = load_dataset("walledai/AdvBench")["train"]
        return [r["prompt"] for r in ds]
    except Exception as e:
        print(f"[advbench] HF load failed ({type(e).__name__}); trying GitHub fallback")
        return None


def _load_advbench_github():
    try:
        with urllib.request.urlopen(ADVBENCH_FALLBACK_URL, timeout=15) as resp:
            text = resp.read().decode("utf-8")
        reader = csv.DictReader(io.StringIO(text))
        return [row["goal"] for row in reader if row.get("goal")]
    except Exception as e:
        print(f"[advbench] GitHub fallback failed: {e}")
        return None


# ---------------------------------------------------------------------------
# Dolly-15k (benign)
# ---------------------------------------------------------------------------
def load_dolly_benign(n: int = 500, seed: int = 42) -> List[EvalPrompt]:
    """
    Loads a sample of benign instructions from databricks-dolly-15k for FPR.
    HuggingFace: databricks/databricks-dolly-15k.

    Filters out rows with non-empty 'context' to keep prompts self-contained
    (otherwise summarization/closed-QA rows have huge passages attached).
    """
    from datasets import load_dataset

    ds = load_dataset("databricks/databricks-dolly-15k")["train"]
    rows = [r for r in ds if not (r.get("context") or "").strip()]
    random.Random(seed).shuffle(rows)
    rows = rows[:n]
    return [
        EvalPrompt(
            text=r["instruction"],
            label="benign",
            source="Dolly-15k",
            behavior=r.get("category", ""),
        )
        for r in rows
        if r.get("instruction", "").strip()
    ]


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------
def load_default_suite(
    n_advbench: int = 100,
    n_dolly: int = 500,
) -> List[EvalPrompt]:
    """The standard evaluation suite used in the paper."""
    return (
        load_jailbreakbench()
        + load_advbench(n=n_advbench)
        + load_dolly_benign(n=n_dolly)
    )


def summarize(prompts: List[EvalPrompt]) -> None:
    """Print a small summary to stdout."""
    from collections import Counter

    by_source = Counter(p.source for p in prompts)
    by_label = Counter(p.label for p in prompts)
    print(f"Loaded {len(prompts)} prompts.")
    print(f"  By source: {dict(by_source)}")
    print(f"  By label:  {dict(by_label)}")


if __name__ == "__main__":
    suite = load_default_suite()
    summarize(suite)
    seen = set()
    for p in suite:
        key = (p.source, p.label)
        if key not in seen:
            print(f"\n[{p.source}/{p.label}] {p.text[:140]}")
            seen.add(key)
