"""
eval/charts.py
--------------
Two charts for the slides:
  1. attribution.png - stacked bars per track (FW / LLM / Complied)
  2. latency.png    - firewall inspection time, LLM time excluded

Reads eval/results/<config>/*.csv via judge.score_track and writes to
    eval/results/<config>/charts/

Usage:
    python -m eval.judge eval/results/full
    python -m eval.charts eval/results/full
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from eval.judge import score_track  # noqa: E402


TRACK_ORDER = [
    "outbound_sysprompt_leak",
    "outbound_pii_leak",
    "inbound_pii",
    "direct_injection",
    "indirect_injection",
]

PRETTY = {
    "outbound_sysprompt_leak": "System-prompt leak\n(outbound)",
    "outbound_pii_leak":       "PII echo\n(outbound)",
    "inbound_pii":             "Inbound PII",
    "direct_injection":        "Direct injection",
    "indirect_injection":      "Indirect injection\n(BIPIA)",
    "benign_control":          "Benign control",
}


def make_attribution_chart(results_dir: Path, out_path: Path) -> None:
    csvs = sorted(p for p in results_dir.glob("*.csv") if not p.stem.startswith("_"))
    rows = {p.stem: score_track(p) for p in csvs}

    tracks = [t for t in TRACK_ORDER if t in rows and rows[t]["n_attacks"]]
    if not tracks:
        raise SystemExit(f"No attack-track CSVs found in {results_dir}")

    labels = [PRETTY.get(t, t) for t in tracks]
    fw   = [rows[t]["fw_blocked_pct"] or 0 for t in tracks]
    llm  = [rows[t]["llm_refused_pct"] or 0 for t in tracks]
    comp = [rows[t]["complied_pct"] or 0 for t in tracks]
    ns   = [rows[t]["n_attacks"] for t in tracks]

    fig, ax = plt.subplots(figsize=(11, 5.5))
    y = list(range(len(tracks)))

    ax.barh(y, fw,   color="#2ca02c", label="Firewall-blocked")
    ax.barh(y, llm,  left=fw, color="#f0c419", label="LLM-refused")
    ax.barh(y, comp, left=[a+b for a, b in zip(fw, llm)],
            color="#d62728", label="Complied (failure)")

    for i in range(len(tracks)):
        if fw[i] >= 5:
            ax.text(fw[i] / 2, i, f"{fw[i]:.0f}%", va="center", ha="center",
                    color="white", fontweight="bold", fontsize=10)
        if llm[i] >= 5:
            ax.text(fw[i] + llm[i] / 2, i, f"{llm[i]:.0f}%", va="center",
                    ha="center", color="#333", fontweight="bold", fontsize=10)
        if comp[i] >= 5:
            ax.text(fw[i] + llm[i] + comp[i] / 2, i, f"{comp[i]:.0f}%",
                    va="center", ha="center", color="white", fontweight="bold", fontsize=10)
        ax.text(101, i, f"N={ns[i]}", va="center", ha="left", fontsize=9, color="#666")

    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=10)
    ax.invert_yaxis()
    ax.set_xlim(0, 115)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.set_xticklabels(["0%", "25%", "50%", "75%", "100%"])
    ax.set_xlabel("Outcome distribution on attack prompts")
    ax.set_title("Defense-in-depth attribution: firewall + LLM by threat track",
                 fontsize=12, pad=14)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, -0.18), ncol=3, frameon=False)
    ax.grid(axis="x", linestyle="--", alpha=0.3)
    ax.set_axisbelow(True)

    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=160, bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote {out_path}")


def make_latency_chart(results_dir: Path, out_path: Path) -> None:
    """
    Firewall inspection latency only - excludes LLM generation time.

    Sum of prompt_inspect_ms + response_inspect_ms per request, then take
    p50 and p95 across each track. This is the *actual firewall overhead*,
    distinct from full request time (which includes 3-15s of Llama 3.2
    generation on prompts that pass through).
    """
    csvs = sorted(p for p in results_dir.glob("*.csv") if not p.stem.startswith("_"))

    track_stats = {}
    for csv_path in csvs:
        df = pd.read_csv(csv_path)
        prompt_ms = pd.to_numeric(df["prompt_inspect_ms"], errors="coerce").fillna(0)
        resp_ms = pd.to_numeric(df["response_inspect_ms"], errors="coerce").fillna(0)
        fw_ms = (prompt_ms + resp_ms).dropna()
        if len(fw_ms):
            track_stats[csv_path.stem] = {
                "p50": fw_ms.quantile(0.50),
                "p95": fw_ms.quantile(0.95),
            }

    tracks = [t for t in TRACK_ORDER if t in track_stats]
    labels = [PRETTY.get(t, t).replace("\n", " ") for t in tracks]
    p50s = [track_stats[t]["p50"] for t in tracks]
    p95s = [track_stats[t]["p95"] for t in tracks]

    fig, ax = plt.subplots(figsize=(11, 4.8))
    x = list(range(len(tracks)))
    w = 0.35
    b1 = ax.bar([i - w/2 for i in x], p50s, w, color="#2ca02c", label="p50")
    b2 = ax.bar([i + w/2 for i in x], p95s, w, color="#ff7f0e", label="p95")

    ymax = max(p95s) * 1.15 if p95s else 100
    for bars in (b1, b2):
        for b in bars:
            h = b.get_height()
            ax.text(b.get_x() + b.get_width()/2, h + ymax * 0.02, f"{h:.1f}",
                    ha="center", fontsize=9)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=10, fontsize=9)
    ax.set_ylabel("Firewall inspection latency (ms)")
    ax.set_ylim(0, ymax)
    ax.set_title("Firewall overhead by track (LLM generation time excluded)",
                 fontsize=12, pad=10)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    ax.set_axisbelow(True)

    fig.text(0.5, -0.02,
             "Inspection time only (Prompt Inspector + Response Inspector). "
             "Full request adds 3-15s of LLM generation on prompts that pass through.",
             ha="center", fontsize=8, style="italic", color="#555")

    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=160, bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote {out_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results_dir", type=Path)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    if not args.results_dir.is_dir():
        raise SystemExit(f"Not a directory: {args.results_dir}")
    out_dir = args.out or (args.results_dir / "charts")

    make_attribution_chart(args.results_dir, out_dir / "attribution.png")
    make_latency_chart(args.results_dir, out_dir / "latency.png")


if __name__ == "__main__":
    main()