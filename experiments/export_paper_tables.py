"""Export cleaned paper tables from B-journal experiment summaries."""

from __future__ import annotations

import argparse
import csv
import re
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Iterable


MAIN_ATTACKS = {"sign_flip", "adaptive_scaling", "backdoor"}
MAIN_METHODS = {"fedavg", "krum", "trimmed_mean", "median", "norm_filter", "proposed"}
EXTENSION_METHODS = {"fedavg", "norm_filter", "proposed", "fltrust"}
FLAME_METHODS = {"fedavg", "norm_filter", "fltrust", "flame", "proposed"}


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_rows(path: Path, rows: Iterable[dict[str, object]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def latest_by_experiment(rows: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    latest: dict[str, dict[str, str]] = {}
    for row in rows:
        name = row["experiment_name"]
        if name not in latest or row["run_dir"] > latest[name]["run_dir"]:
            latest[name] = row
    return list(latest.values())


def f(row: dict[str, str], key: str) -> float:
    value = row.get(key, "")
    try:
        return float(value)
    except ValueError:
        return float("nan")


def b(row: dict[str, str], key: str) -> bool:
    return str(row.get(key, "")).lower() == "true"


def mean(values: list[float]) -> float:
    values = [v for v in values if v == v]
    return statistics.mean(values) if values else float("nan")


def stdev(values: list[float]) -> float:
    values = [v for v in values if v == v]
    return statistics.stdev(values) if len(values) > 1 else 0.0


def r2(value: float) -> float:
    return round(value, 2) if value == value else value


def seed_from_name(name: str) -> int | None:
    match = re.search(r"_s(\d+)$", name)
    return int(match.group(1)) if match else None


def ablation_variant_from_name(name: str) -> str:
    match = re.search(
        r"^ablation_fashionmnist_noniid_(?P<attack>.+?)_(?P<variant>full|no_direction|no_history|no_hard_reject)_s\d+$",
        name,
    )
    return match.group("variant") if match else ""


def coefficient_variant_from_name(name: str) -> str:
    match = re.search(
        r"^sensitivity_fashionmnist_noniid_(?P<attack>.+?)_"
        r"(?P<variant>default|norm_heavy|direction_heavy|history_heavy|balanced)_s\d+$",
        name,
    )
    return match.group("variant") if match else ""


def aggregate(rows: list[dict[str, str]], group_keys: list[str]) -> list[dict[str, object]]:
    groups: dict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[tuple(row[key] for key in group_keys)].append(row)

    table: list[dict[str, object]] = []
    for key, group in groups.items():
        acc = [f(row, "final_clean_accuracy") for row in group]
        best = [f(row, "best_clean_accuracy") for row in group]
        asr = [f(row, "final_backdoor_asr") for row in group]
        loss = [f(row, "final_test_loss") for row in group]
        rounds = [int(float(row["num_rounds"])) for row in group if row.get("num_rounds")]
        record: dict[str, object] = dict(zip(group_keys, key))
        record.update(
            {
                "n": len(group),
                "acc_mean": r2(mean(acc)),
                "acc_std": r2(stdev(acc)),
                "best_acc_mean": r2(mean(best)),
                "asr_mean": r2(mean(asr)),
                "asr_std": r2(stdev(asr)),
                "loss_mean": round(mean(loss), 4),
                "early_stop_count": sum(1 for value in rounds if value < max(rounds or [0])),
            }
        )
        table.append(record)
    return sorted(table, key=lambda row: tuple(str(row[key]) for key in group_keys))


def markdown_table(rows: list[dict[str, object]], fieldnames: list[str]) -> str:
    header = "| " + " | ".join(fieldnames) + " |"
    sep = "| " + " | ".join(["---"] * len(fieldnames)) + " |"
    body = []
    for row in rows:
        body.append("| " + " | ".join(str(row.get(field, "")) for field in fieldnames) + " |")
    return "\n".join([header, sep, *body])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", default="experiments_b_journal/summary_table.csv")
    parser.add_argument("--out-dir", default="experiments_b_journal/paper_tables")
    args = parser.parse_args()

    summary_path = Path(args.summary)
    out_dir = Path(args.out_dir)

    all_rows = read_rows(summary_path)
    latest = latest_by_experiment(all_rows)

    formal = [
        row
        for row in latest
        if row["experiment_name"].startswith(("core_fashionmnist_", "core_cifar10_", "core_ratio_"))
        and not row["experiment_name"].startswith("core_extra_")
        and not row["experiment_name"].startswith("tune_")
    ]
    extension = [
        row
        for row in latest
        if row["experiment_name"].startswith(("ext_fltrust_", "ext_collusive_", "ext_flame_"))
    ]
    ablation = [
        row
        for row in latest
        if row["experiment_name"].startswith("ablation_")
    ]
    sensitivity = [
        row
        for row in latest
        if row["experiment_name"].startswith("sensitivity_")
    ]

    formal_fields = list(all_rows[0].keys())
    write_rows(out_dir / "formal_latest_results.csv", formal, formal_fields)
    write_rows(out_dir / "extension_latest_results.csv", extension, formal_fields)
    write_rows(out_dir / "ablation_latest_results.csv", ablation, formal_fields)
    write_rows(out_dir / "sensitivity_latest_results.csv", sensitivity, formal_fields)

    fashion_main = [
        row
        for row in formal
        if row["dataset"] == "FashionMNIST"
        and row["experiment_name"].startswith("core_fashionmnist_")
        and row["attack_type"] in MAIN_ATTACKS
        and row["aggregation"] in MAIN_METHODS
        and seed_from_name(row["experiment_name"]) in {42, 43, 44}
    ]
    cifar_noniid = [
        row
        for row in formal
        if row["dataset"] == "CIFAR10"
        and row["experiment_name"].startswith("core_cifar10_noniid_")
        and row["attack_type"] in MAIN_ATTACKS
        and row["aggregation"] in MAIN_METHODS
        and seed_from_name(row["experiment_name"]) in {42, 43, 44}
    ]
    ratio_rows = [
        row
        for row in formal
        if row["experiment_name"].startswith("core_ratio_fashionmnist_noniid_adaptive_")
        and row["aggregation"] in {"proposed", "trimmed_mean", "norm_filter"}
    ]
    fltrust_rows = [
        row
        for row in extension
        if row["experiment_name"].startswith("ext_fltrust_")
        and row["attack_type"] in MAIN_ATTACKS
        and row["aggregation"] == "fltrust"
        and seed_from_name(row["experiment_name"]) in {42, 43, 44}
    ]
    collusive_rows = [
        row
        for row in extension
        if row["experiment_name"].startswith("ext_collusive_")
        and row["attack_type"] == "collusive_direction"
        and row["aggregation"] in EXTENSION_METHODS
        and seed_from_name(row["experiment_name"]) in {42, 43, 44}
    ]
    flame_rows = [
        row
        for row in extension
        if row["experiment_name"].startswith("ext_flame_")
        and row["attack_type"] == "backdoor"
        and row["aggregation"] in FLAME_METHODS
        and seed_from_name(row["experiment_name"]) in {42, 43, 44}
    ]
    ablation_rows = [
        {**row, "ablation_variant": row.get("ablation_variant") or ablation_variant_from_name(row["experiment_name"])}
        for row in ablation
        if row["dataset"] == "FashionMNIST"
        and row["aggregation"] == "proposed"
        and seed_from_name(row["experiment_name"]) in {42, 43, 44}
        and ablation_variant_from_name(row["experiment_name"])
    ]
    sensitivity_rows = [
        {
            **row,
            "coefficient_variant": row.get("coefficient_variant")
            or coefficient_variant_from_name(row["experiment_name"]),
        }
        for row in sensitivity
        if row["dataset"] == "FashionMNIST"
        and row["aggregation"] == "proposed"
        and row["attack_type"] in {"sign_flip", "adaptive_scaling"}
        and seed_from_name(row["experiment_name"]) in {42, 43, 44}
        and coefficient_variant_from_name(row["experiment_name"])
    ]

    fashion_table = aggregate(fashion_main, ["dataset", "iid", "attack_type", "aggregation"])
    cifar_table = aggregate(cifar_noniid, ["dataset", "iid", "attack_type", "aggregation"])
    ratio_table = aggregate(ratio_rows, ["malicious_ratio", "aggregation"])
    fltrust_table = aggregate(fltrust_rows, ["dataset", "iid", "attack_type", "aggregation"])
    collusive_table = aggregate(collusive_rows, ["dataset", "iid", "attack_type", "aggregation"])
    flame_table = aggregate(flame_rows, ["dataset", "iid", "attack_type", "aggregation"])
    ablation_table = aggregate(ablation_rows, ["attack_type", "ablation_variant"])
    sensitivity_table = aggregate(sensitivity_rows, ["attack_type", "coefficient_variant"])

    agg_fields = [
        "dataset",
        "iid",
        "attack_type",
        "aggregation",
        "n",
        "acc_mean",
        "acc_std",
        "best_acc_mean",
        "asr_mean",
        "asr_std",
        "loss_mean",
        "early_stop_count",
    ]
    ratio_fields = [
        "malicious_ratio",
        "aggregation",
        "n",
        "acc_mean",
        "acc_std",
        "best_acc_mean",
        "asr_mean",
        "asr_std",
        "loss_mean",
        "early_stop_count",
    ]

    write_rows(out_dir / "fashionmnist_main_table.csv", fashion_table, agg_fields)
    write_rows(out_dir / "cifar10_noniid_main_table.csv", cifar_table, agg_fields)
    write_rows(out_dir / "ratio_sensitivity_table.csv", ratio_table, ratio_fields)
    write_rows(out_dir / "fltrust_extension_table.csv", fltrust_table, agg_fields)
    write_rows(out_dir / "collusive_extension_table.csv", collusive_table, agg_fields)
    write_rows(out_dir / "flame_backdoor_extension_table.csv", flame_table, agg_fields)
    ablation_fields = [
        "attack_type",
        "ablation_variant",
        "n",
        "acc_mean",
        "acc_std",
        "best_acc_mean",
        "asr_mean",
        "asr_std",
        "loss_mean",
        "early_stop_count",
    ]
    write_rows(out_dir / "proposed_ablation_table.csv", ablation_table, ablation_fields)
    sensitivity_fields = [
        "attack_type",
        "coefficient_variant",
        "n",
        "acc_mean",
        "acc_std",
        "best_acc_mean",
        "asr_mean",
        "asr_std",
        "loss_mean",
        "early_stop_count",
    ]
    write_rows(out_dir / "coefficient_sensitivity_table.csv", sensitivity_table, sensitivity_fields)

    proposed_norm = [
        row
        for row in fashion_table + cifar_table
        if row["aggregation"] in {"proposed", "norm_filter"}
    ]
    write_rows(out_dir / "proposed_vs_norm_filter.csv", proposed_norm, agg_fields)

    md = [
        "# Paper Tables",
        "",
        "## FashionMNIST Main Results",
        markdown_table(fashion_table, agg_fields),
        "",
        "## CIFAR-10 Non-IID Main Results",
        markdown_table(cifar_table, agg_fields),
        "",
        "## Malicious Ratio Sensitivity",
        markdown_table(ratio_table, ratio_fields),
        "",
        "## FLTrust Extension",
        markdown_table(fltrust_table, agg_fields),
        "",
        "## Collusive Direction Attack Extension",
        markdown_table(collusive_table, agg_fields),
        "",
        "## FLAME Backdoor Extension",
        markdown_table(flame_table, agg_fields),
        "",
        "## Proposed Ablation",
        markdown_table(ablation_table, ablation_fields),
        "",
        "## Coefficient Sensitivity",
        markdown_table(sensitivity_table, sensitivity_fields),
        "",
        "## Interpretation Notes",
        "- Use one latest run per experiment_name.",
        "- Exclude smoke, tune, and core_extra diagnostic experiments from main tables.",
        "- Proposed should be described as auditable and competitive, not as uniformly accuracy-best.",
        "- Norm Filter is the strongest clean-accuracy baseline on CIFAR-10 Non-IID.",
        "- FLTrust rows use a trusted root set and should be interpreted under a different trust assumption.",
        "- Collusive-direction rows stress-test coordinated malicious updates in Non-IID settings.",
        "- FLAME rows evaluate a backdoor-specific clustering, clipping, and noise-injection baseline.",
        "- Ablation rows isolate direction scoring, history scoring, and hard rejection in the proposed method.",
        "- Coefficient-sensitivity rows test whether the proposed method depends on one exact anomaly-score weighting.",
    ]
    (out_dir / "paper_tables.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print(f"Wrote paper tables to {out_dir}")
    print(f"Formal latest rows: {len(formal)}")
    print(f"Extension latest rows: {len(extension)}")
    print(f"Ablation latest rows: {len(ablation)}")
    print(f"Sensitivity latest rows: {len(sensitivity)}")
    print(f"FashionMNIST main rows: {len(fashion_main)} -> {len(fashion_table)} grouped rows")
    print(f"CIFAR-10 Non-IID rows: {len(cifar_noniid)} -> {len(cifar_table)} grouped rows")
    print(f"Ratio rows: {len(ratio_rows)} -> {len(ratio_table)} grouped rows")
    print(f"FLTrust extension rows: {len(fltrust_rows)} -> {len(fltrust_table)} grouped rows")
    print(f"Collusive extension rows: {len(collusive_rows)} -> {len(collusive_table)} grouped rows")
    print(f"FLAME extension rows: {len(flame_rows)} -> {len(flame_table)} grouped rows")
    print(f"Ablation rows: {len(ablation_rows)} -> {len(ablation_table)} grouped rows")
    print(f"Sensitivity rows: {len(sensitivity_rows)} -> {len(sensitivity_table)} grouped rows")


if __name__ == "__main__":
    main()
