# CheesyWasp — Evaluation Harness

Quantitative evaluation of the firewall against public prompt-injection /
jailbreak benchmarks, plus head-to-head comparison with Llama Guard 3 and
Prompt Guard 2.

## Install

Append to `requirements.txt`:

```
datasets>=2.18
requests>=2.31
tqdm>=4.66
pandas>=2.0
matplotlib>=3.7
transformers>=4.43         # baselines only
torch>=2.1                  # baselines only
```

Then `pip install -r requirements.txt`.

Some datasets / models are gated on HuggingFace:

```bash
huggingface-cli login
```

Then visit and accept the terms (one-time):
- AdvBench: https://huggingface.co/datasets/walledai/AdvBench (the loader auto-falls-back to the original `llm-attacks` GitHub CSV if HF refuses)
- Llama Guard 3 1B: https://huggingface.co/meta-llama/Llama-Guard-3-1B
- Prompt Guard 2 86M: https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M

## Datasets

| Source | Role | Size used | Citation |
|---|---|---|---|
| JailbreakBench (JBB-Behaviors) | ASR + FPR | 100 harmful + 100 benign | Chao et al. 2024, arXiv:2404.01318 |
| AdvBench | ASR | 100 (sampled, seed=42) | Zou et al. 2023, arXiv:2307.15043 |
| Dolly-15k | FPR | 500 (sampled, seed=42, no-context) | Databricks 2023 |

## How to evaluate the three CheesyWasp configurations

The firewall server is expected to expose a way to toggle layers. Three
recommended approaches (pick one):

**Option A — env var (cleanest):** read `FIREWALL_MODE` at server startup.

```bash
# Terminal 1
FIREWALL_MODE=none uvicorn api.server:app --port 8000
# Terminal 2
python -m eval.run_eval --output eval/results/no_firewall.csv
```

Repeat with `FIREWALL_MODE=l1` and `FIREWALL_MODE=full`, writing to
`l1_only.csv` and `full.csv` respectively.

**Option B — extra JSON field:** make `/v1/chat` accept `{"prompt": ..., "config": "l1_only"}`. Then:

```bash
python -m eval.run_eval --output eval/results/l1_only.csv \
    --extra-param config=l1_only
```

**Option C — three deployments on different ports.** Simplest for a demo.

## Baselines

```bash
python -m eval.baselines --model prompt-guard --output eval/results/promptguard.csv
python -m eval.baselines --model llama-guard  --output eval/results/llamaguard.csv
```

Llama Guard 3 1B is meaningfully slower on CPU (~200ms+ per prompt). Budget
~5 min for JBB+AdvBench combined, ~25 min if you also include all 500 Dolly
prompts. For the demo it's fine to subsample with `--n-dolly 100`.

## Generate the charts

Once all CSVs are in `eval/results/`:

```bash
python -m eval.charts --results eval/results --out eval/results/charts
```

Produces:
- `summary.csv` — one row per configuration, columns: ASR, FPR, p50_ms, p95_ms
- `asr_fpr.png` — the headline chart for slide 7
- `latency.png` — the latency chart for slide 7
- `per_dataset.csv` — config × dataset breakdown for the appendix

## What the metrics mean

- **ASR (Attack Success Rate)** — fraction of *harmful* prompts that the
  firewall let through. Lower is better. Computed only on rows where
  `label == "harmful"`.
- **FPR (False Positive Rate)** — fraction of *benign* prompts that the
  firewall incorrectly blocked. Lower is better. This is the
  over-defense metric from InjecGuard (Li et al. 2024).
- **p50 / p95 latency** — server-reported `total_ms` from the firewall's
  audit trail; falls back to client wall-clock if not present.

Note that for the "no firewall" config, ASR is whatever the *protected
LLM itself* refuses on its own, since the firewall is a pass-through. That
number is your baseline — the firewall has to improve on it without
overshooting FPR.
