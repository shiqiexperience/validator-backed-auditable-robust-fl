"""Summarize B-journal benchmark outputs into a paper-table CSV."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


FIELDS = [
    "run_dir",
    "experiment_name",
    "dataset",
    "iid",
    "alpha",
    "aggregation",
    "attack_type",
    "malicious_ratio",
    "num_rounds",
    "final_clean_accuracy",
    "best_clean_accuracy",
    "final_test_loss",
    "final_backdoor_asr",
    "final_rejection_rate",
    "final_tpr",
    "final_fpr",
    "final_f1",
    "chain_valid",
    "total_time",
]


def read_json(path: Path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def read_round_metrics(path: Path):
    with open(path, "r", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def summarize_run(run_dir: Path):
    config_path = run_dir / "config.json"
    summary_path = run_dir / "summary.json"
    metrics_path = run_dir / "metrics_round.csv"
    if not (config_path.exists() and summary_path.exists() and metrics_path.exists()):
        return None

    config = read_json(config_path)
    summary = read_json(summary_path)
    metrics = read_round_metrics(metrics_path)
    if not metrics:
        return None

    final = metrics[-1]
    best_acc = max(float(row["clean_accuracy"]) for row in metrics)

    return {
        "run_dir": str(run_dir),
        "experiment_name": config.get("experiment_name", ""),
        "dataset": config.get("dataset", ""),
        "iid": config.get("iid", ""),
        "alpha": config.get("alpha", ""),
        "aggregation": config.get("aggregation", summary.get("aggregation", "")),
        "attack_type": config.get("attack_type", summary.get("attack_type", "")),
        "malicious_ratio": config.get("malicious_ratio", ""),
        "num_rounds": config.get("num_rounds", ""),
        "final_clean_accuracy": final.get("clean_accuracy", ""),
        "best_clean_accuracy": best_acc,
        "final_test_loss": final.get("test_loss", ""),
        "final_backdoor_asr": final.get("backdoor_asr", ""),
        "final_rejection_rate": final.get("rejection_rate", ""),
        "final_tpr": final.get("tpr", ""),
        "final_fpr": final.get("fpr", ""),
        "final_f1": final.get("f1", ""),
        "chain_valid": summary.get("chain_valid", ""),
        "total_time": summary.get("total_time", ""),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", default="experiments_b_journal")
    parser.add_argument("--out", default="experiments_b_journal/summary_table.csv")
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    rows = []
    for run_dir in sorted(results_dir.iterdir() if results_dir.exists() else []):
        if run_dir.is_dir():
            row = summarize_run(run_dir)
            if row is not None:
                rows.append(row)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {out_path}")


if __name__ == "__main__":
    main()

