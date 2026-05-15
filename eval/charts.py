"""
eval/charts.py
--------------
Compute per-configuration metrics (ASR, FPR, latency) from result CSVs and
generate the two charts that go in the slides and the writeup.

Outputs:
    eval/results/charts/summary.csv          - one row per CSV in --results
    eval/results/charts/asr_fpr.png          - grouped bar chart
    eval/results/charts/latency.png          - p50/p95 bars
    eval/results/charts/per_dataset.csv      - per-(config, source) breakdown

Usage:
    python -m eval.charts --results eval/results --out eval/results/charts
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict

import matplotlib.pyplot as plt
import pandas as pd


# A consistent ordering for prettier charts; any unrecognized config is appended.
PREFERRED_ORDER = ["no_firewall", "l1_only", "full", "promptguard", "llamaguard"]
PRETTY = {
    "no_firewall": "No firewall",
    "l1_only": "L1 (regex)",
    "full": "L1 + L2 (full)",
    "promptguard": "Prompt Guard 2",
    "llamaguard": "Llama Guard 3",
}


def _bool(s) -> bool:
    return str(s).strip().lower() in {"true", "1", "yes"}


def _latency_col(df: pd.DataFrame) -> str:
    """Prefer firewall-reported total_ms; fall back to client wall-clock."""
    if "total_ms" in df.columns and pd.to_numeric(df["total_ms"], errors="coerce").notna().any():
        return "total_ms"
    return "client_total_ms"


def compute_metrics(df: pd.DataFrame) -> dict:
    df = df.copy()
    df["allowed_b"] = df["allowed"].apply(_bool)
    harmful = df[df["label"] == "harmful"]
    benign = df[df["label"] == "benign"]
    asr = harmful["allowed_b"].mean() if len(harmful) else float("nan")
    fpr = (~benign["allowed_b"]).mean() if len(benign) else float("nan")
    lat_col = _latency_col(df)
    lat = pd.to_numeric(df[lat_col], errors="coerce").dropna()
    return {
        "ASR": asr,
        "FPR": fpr,
        "p50_ms": lat.quantile(0.50) if len(lat) else float("nan"),
        "p95_ms": lat.quantile(0.95) if len(lat) else float("nan"),
        "mean_ms": lat.mean() if len(lat) else float("nan"),
        "n_harmful": len(harmful),
        "n_benign": len(benign),
    }


def compute_per_dataset(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["allowed_b"] = df["allowed"].apply(_bool)
    out = []
    for (src, label), group in df.groupby(["source", "label"]):
        allowed_rate = group["allowed_b"].mean()
        out.append(
            {
                "source": src,
                "label": label,
                "n": len(group),
                "allowed_rate": allowed_rate,
                "blocked_rate": 1 - allowed_rate,
            }
        )
    return pd.DataFrame(out)


def _order(configs: Dict[str, dict]) -> list:
    keys = list(configs.keys())
    ranked = [k for k in PREFERRED_ORDER if k in keys]
    extras = [k for k in keys if k not in PREFERRED_ORDER]
    return ranked + sorted(extras)


def make_charts(results_dir: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    configs: Dict[str, dict] = {}
    per_dataset_rows = []
    for csv_path in sorted(results_dir.glob("*.csv")):
        if csv_path.name == "summary.csv" or csv_path.parent.name == "charts":
            continue
        name = csv_path.stem
        df = pd.read_csv(csv_path)
        configs[name] = compute_metrics(df)
        pd_df = compute_per_dataset(df)
        pd_df["config"] = name
        per_dataset_rows.append(pd_df)

    if not configs:
        raise SystemExit(f"No CSVs found in {results_dir}")

    summary = pd.DataFrame(configs).T
    summary = summary.loc[_order(configs)]
    summary.to_csv(out_dir / "summary.csv")
    print("\n=== Summary ===")
    with pd.option_context("display.float_format", "{:.3f}".format):
        print(summary)

    per_dataset = pd.concat(per_dataset_rows, ignore_index=True)
    per_dataset.to_csv(out_dir / "per_dataset.csv", index=False)

    labels = [PRETTY.get(k, k) for k in summary.index]

    # Chart 1: ASR vs FPR
    fig, ax = plt.subplots(figsize=(9, 5))
    x = list(range(len(summary)))
    width = 0.35
    bars1 = ax.bar(
        [i - width / 2 for i in x],
        (summary["ASR"] * 100).values,
        width,
        label="ASR  (↓ better)",
        color="#d62728",
    )
    bars2 = ax.bar(
        [i + width / 2 for i in x],
        (summary["FPR"] * 100).values,
        width,
        label="FPR  (↓ better)",
        color="#1f77b4",
    )
    for b in list(bars1) + list(bars2):
        h = b.get_height()
        if pd.notna(h):
            ax.text(b.get_x() + b.get_width() / 2, h + 0.5, f"{h:.1f}", ha="center", fontsize=9)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15)
    ax.set_ylabel("Rate (%)")
    ax.set_title("Attack Success Rate vs False Positive Rate")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_dir / "asr_fpr.png", dpi=160)
    plt.close(fig)

    # Chart 2: Latency
    fig, ax = plt.subplots(figsize=(9, 5))
    bars1 = ax.bar(
        [i - width / 2 for i in x],
        summary["p50_ms"].values,
        width,
        label="p50",
        color="#2ca02c",
    )
    bars2 = ax.bar(
        [i + width / 2 for i in x],
        summary["p95_ms"].values,
        width,
        label="p95",
        color="#ff7f0e",
    )
    for b in list(bars1) + list(bars2):
        h = b.get_height()
        if pd.notna(h):
            ax.text(b.get_x() + b.get_width() / 2, h + 2, f"{h:.0f}", ha="center", fontsize=9)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15)
    ax.set_ylabel("Latency (ms)")
    ax.set_title("End-to-End Latency by Configuration")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_dir / "latency.png", dpi=160)
    plt.close(fig)

    print(f"\nCharts -> {out_dir}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="eval/results")
    ap.add_argument("--out", default="eval/results/charts")
    args = ap.parse_args()
    make_charts(Path(args.results), Path(args.out))


if __name__ == "__main__":
    main()
