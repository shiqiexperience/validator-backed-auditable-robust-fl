"""Export runtime and audit-log overhead summaries from formal runs."""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

import pandas as pd


def read_latest(summary: Path) -> list[dict[str, str]]:
    with summary.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    latest: dict[str, dict[str, str]] = {}
    for row in rows:
        name = row["experiment_name"]
        if name not in latest or row["run_dir"] > latest[name]["run_dir"]:
            latest[name] = row
    return list(latest.values())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", default="experiments_b_journal/summary_table.csv")
    parser.add_argument("--out", default="experiments_b_journal/paper_tables/overhead_table.csv")
    args = parser.parse_args()

    latest = read_latest(Path(args.summary))
    formal = [
        row
        for row in latest
        if row["experiment_name"].startswith(("core_fashionmnist_", "core_cifar10_noniid_"))
        and row["aggregation"] in {"fedavg", "krum", "trimmed_mean", "median", "norm_filter", "proposed"}
        and row["attack_type"] in {"sign_flip", "adaptive_scaling", "backdoor"}
    ]

    groups: dict[tuple[str, str], list[dict[str, float]]] = defaultdict(list)
    for row in formal:
        run_dir = Path(row["run_dir"])
        metrics_path = run_dir / "metrics_round.csv"
        audit_path = run_dir / "audit_chain.jsonl"
        if not metrics_path.exists():
            continue
        metrics = pd.read_csv(metrics_path)
        groups[(row["dataset"], row["aggregation"])].append(
            {
                "round_time": float(metrics["round_time"].mean()),
                "defense_time": float(metrics["defense_time"].mean()),
                "audit_kb": audit_path.stat().st_size / 1024.0 if audit_path.exists() else 0.0,
                "rounds": float(len(metrics)),
            }
        )

    out_rows = []
    for (dataset, aggregation), values in sorted(groups.items()):
        out_rows.append(
            {
                "dataset": dataset,
                "aggregation": aggregation,
                "runs": len(values),
                "mean_round_time_sec": round(sum(v["round_time"] for v in values) / len(values), 4),
                "mean_defense_time_sec": round(sum(v["defense_time"] for v in values) / len(values), 6),
                "mean_audit_log_kb": round(sum(v["audit_kb"] for v in values) / len(values), 2),
                "mean_rounds": round(sum(v["rounds"] for v in values) / len(values), 1),
            }
        )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "dataset",
                "aggregation",
                "runs",
                "mean_round_time_sec",
                "mean_defense_time_sec",
                "mean_audit_log_kb",
                "mean_rounds",
            ],
        )
        writer.writeheader()
        writer.writerows(out_rows)
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
