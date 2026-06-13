"""Export quantitative auditability metrics from a recorded audit case."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
from copy import deepcopy
from pathlib import Path
from typing import Any


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_payload(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def load_blocks(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def verify_blocks(blocks: list[dict[str, Any]]) -> bool:
    previous = "0" * 64
    for original in blocks:
        block = deepcopy(original)
        found_hash = block.pop("hash", "")
        if block.get("previous_hash") != previous:
            return False
        if hash_payload(block) != found_hash:
            return False
        previous = found_hash
    return True


def tamper_detection_rate(blocks: list[dict[str, Any]]) -> tuple[int, int, float]:
    detected = 0
    for index in range(len(blocks)):
        tampered = deepcopy(blocks)
        metrics = tampered[index]["payload"].setdefault("metrics", {})
        metrics["clean_accuracy"] = float(metrics.get("clean_accuracy", 0.0)) + 0.12345
        if not verify_blocks(tampered):
            detected += 1
    total = len(blocks)
    return detected, total, detected / total if total else 0.0


def decision_reconstruction_rate(blocks: list[dict[str, Any]]) -> tuple[int, int, float]:
    required = {
        "client_id",
        "norm",
        "direction",
        "norm_score",
        "history_score",
        "anomaly_score",
        "reputation_before",
        "reputation_after",
        "aggregation_weight",
        "rejected",
    }
    reconstructable = 0
    total = 0
    for block in blocks:
        clients = {int(row["client_id"]): row for row in block["payload"].get("clients", [])}
        for decision in block["payload"].get("decisions", []):
            total += 1
            if not required.issubset(decision):
                continue
            client_id = int(decision["client_id"])
            client = clients.get(client_id)
            if client is None:
                continue
            weight_match = abs(float(client["aggregation_weight"]) - float(decision["aggregation_weight"])) < 1e-9
            rejection_match = (float(decision["rejected"]) > 0.5) == (float(decision["aggregation_weight"]) <= 1e-12)
            if weight_match and rejection_match:
                reconstructable += 1
    return reconstructable, total, reconstructable / total if total else 0.0


def load_client_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def influence_metrics(rows: list[dict[str, str]]) -> dict[str, float]:
    malicious = [r for r in rows if int(float(r["is_malicious"])) == 1]
    benign = [r for r in rows if int(float(r["is_malicious"])) == 0]
    eps = 1e-12

    def mean_weight(subset: list[dict[str, str]]) -> float:
        return sum(float(r["aggregation_weight"]) for r in subset) / len(subset) if subset else 0.0

    def zero_rate(subset: list[dict[str, str]]) -> float:
        return sum(float(r["aggregation_weight"]) <= eps for r in subset) / len(subset) if subset else 0.0

    def nonzero_rate(subset: list[dict[str, str]]) -> float:
        return sum(float(r["aggregation_weight"]) > eps for r in subset) / len(subset) if subset else 0.0

    malicious_mean = mean_weight(malicious)
    benign_mean = mean_weight(benign)
    return {
        "malicious_mean_weight": malicious_mean,
        "benign_mean_weight": benign_mean,
        "weight_gap": benign_mean - malicious_mean,
        "malicious_suppression_rate": zero_rate(malicious),
        "benign_retention_rate": nonzero_rate(benign),
        "client_rounds": float(len(rows)),
        "malicious_client_rounds": float(len(malicious)),
        "benign_client_rounds": float(len(benign)),
    }


def round_detection_metrics(path: Path) -> dict[str, float]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    fields = ["precision", "recall", "f1", "false_rejection_rate"]
    result: dict[str, float] = {}
    for field in fields:
        values = [float(r[field]) for r in rows if r.get(field, "") != ""]
        result[f"mean_{field}"] = sum(values) / len(values) if values else 0.0
    return result


def compute_run_metrics(run_dir: Path) -> dict[str, Any]:
    config = load_json(run_dir / "config.json")
    summary = load_json(run_dir / "summary.json") if (run_dir / "summary.json").exists() else {}
    blocks = load_blocks(run_dir / "audit_chain.jsonl")
    chain_valid = verify_blocks(blocks)
    tampered, tamper_total, tamper_rate = tamper_detection_rate(blocks)
    reconstructed, decisions, reconstruction_rate = decision_reconstruction_rate(blocks)
    influence = influence_metrics(load_client_rows(run_dir / "client_round_metrics.csv"))
    detection = round_detection_metrics(run_dir / "metrics_round.csv")

    split = "IID" if bool(config.get("iid")) else "Non-IID"
    suite = "ratio" if str(config.get("experiment_name", "")).startswith("core_ratio_") else "main"
    malicious_ratio = float(config.get("malicious_ratio", 0.0))
    return {
        "run_dir": str(run_dir),
        "experiment_name": str(config.get("experiment_name", run_dir.name)),
        "suite": suite,
        "dataset": str(config.get("dataset", "")),
        "split": split,
        "attack_type": str(config.get("attack_type", "")),
        "seed": int(config.get("seed", -1)),
        "malicious_ratio": malicious_ratio,
        "rounds": len(blocks),
        "final_accuracy": float(summary.get("final_accuracy", 0.0)),
        "final_asr": float(summary.get("final_asr", 0.0)),
        "chain_verification_rate": 1.0 if chain_valid else 0.0,
        "tamper_detection_rate": tamper_rate,
        "tampered_blocks_detected": tampered,
        "tampered_blocks_total": tamper_total,
        "decision_reconstruction_rate": reconstruction_rate,
        "reconstructed_decisions": reconstructed,
        "total_decisions": decisions,
        "malicious_suppression_rate": influence["malicious_suppression_rate"],
        "benign_retention_rate": influence["benign_retention_rate"],
        "malicious_mean_weight": influence["malicious_mean_weight"],
        "benign_mean_weight": influence["benign_mean_weight"],
        "weight_gap": influence["weight_gap"],
        "mean_rejection_precision": detection["mean_precision"],
        "mean_rejection_recall": detection["mean_recall"],
        "mean_rejection_f1": detection["mean_f1"],
        "mean_false_rejection_rate": detection["mean_false_rejection_rate"],
    }


def discover_latest_runs(results_dir: Path) -> list[Path]:
    candidates: dict[str, tuple[str, Path]] = {}
    for run_dir in results_dir.iterdir():
        if not run_dir.is_dir():
            continue
        if not run_dir.name.startswith(("core_", "core_ratio_")):
            continue
        if "proposed" not in run_dir.name:
            continue
        if run_dir.name.startswith("tune_"):
            continue
        required = ["config.json", "summary.json", "audit_chain.jsonl", "client_round_metrics.csv", "metrics_round.csv"]
        if not all((run_dir / name).exists() for name in required):
            continue
        config = load_json(run_dir / "config.json")
        experiment_name = str(config.get("experiment_name", run_dir.name))
        started_at = str(config.get("started_at", run_dir.name.rsplit("_", 1)[-1]))
        current = candidates.get(experiment_name)
        if current is None or started_at > current[0]:
            candidates[experiment_name] = (started_at, run_dir)
    return [item[1] for item in sorted(candidates.values(), key=lambda row: row[1].name)]


def write_dict_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def mean_std(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    if len(values) == 1:
        return values[0], 0.0
    return statistics.mean(values), statistics.stdev(values)


def aggregate_rows(rows: list[dict[str, Any]], keys: list[str]) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(tuple(row[key] for key in keys), []).append(row)

    metrics = [
        "chain_verification_rate",
        "tamper_detection_rate",
        "decision_reconstruction_rate",
        "malicious_suppression_rate",
        "benign_retention_rate",
        "weight_gap",
        "mean_rejection_precision",
        "mean_rejection_recall",
        "mean_false_rejection_rate",
        "final_accuracy",
        "final_asr",
    ]
    out: list[dict[str, Any]] = []
    for group_key, group_rows in sorted(groups.items()):
        record = {key: value for key, value in zip(keys, group_key)}
        record["runs"] = len(group_rows)
        record["seeds"] = ",".join(str(row["seed"]) for row in sorted(group_rows, key=lambda r: r["seed"]))
        for metric in metrics:
            values = [float(row[metric]) for row in group_rows]
            avg, std = mean_std(values)
            record[f"{metric}_mean"] = avg
            record[f"{metric}_std"] = std
        out.append(record)
    return out


def overview_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups = [
        ("Main benchmark", [row for row in rows if row["suite"] == "main"]),
        ("Malicious-ratio sensitivity", [row for row in rows if row["suite"] == "ratio"]),
        ("All proposed runs", rows),
    ]
    metrics = [
        "chain_verification_rate",
        "tamper_detection_rate",
        "decision_reconstruction_rate",
        "benign_retention_rate",
    ]
    out: list[dict[str, Any]] = []
    for label, group_rows in groups:
        record: dict[str, Any] = {
            "scope": label,
            "runs": len(group_rows),
            "audit_blocks": sum(int(row["rounds"]) for row in group_rows),
            "client_round_decisions": sum(int(row["total_decisions"]) for row in group_rows),
        }
        for metric in metrics:
            avg, std = mean_std([float(row[metric]) for row in group_rows])
            record[f"{metric}_mean"] = avg
            record[f"{metric}_std"] = std
        out.append(record)
    return out


def pct_mean_std(row: dict[str, Any], metric: str) -> str:
    return f"{100 * float(row[f'{metric}_mean']):.2f} $\\pm$ {100 * float(row[f'{metric}_std']):.2f}"


def val_mean_std(row: dict[str, Any], metric: str) -> str:
    return f"{float(row[f'{metric}_mean']):.4f} $\\pm$ {float(row[f'{metric}_std']):.4f}"


def write_latex_table(path: Path, grouped_rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        r"\begin{tabular}{lllrrrrr}",
        r"\toprule",
        r"Dataset & Split & Attack & Runs & Chain & Reconstruction & Suppression & Retention \\",
        r"\midrule",
    ]
    for row in grouped_rows:
        if row["suite"] != "main":
            continue
        line = (
            f"{row['dataset']} & {row['split']} & {str(row['attack_type']).replace('_', '-')}"
            f" & {row['runs']} & {pct_mean_std(row, 'chain_verification_rate')}"
            f" & {pct_mean_std(row, 'decision_reconstruction_rate')}"
            f" & {pct_mean_std(row, 'malicious_suppression_rate')}"
            f" & {pct_mean_std(row, 'benign_retention_rate')} \\\\"
        )
        lines.append(line)
    lines.extend([r"\bottomrule", r"\end{tabular}"])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_metrics_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["metric", "value", "unit", "definition"])
        writer.writeheader()
        writer.writerows(rows)


def percent(value: float) -> str:
    return f"{value * 100:.2f}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--run-dir",
        default="experiments_b_journal/core_fashionmnist_noniid_sign_flip_proposed_s42_20260607_101012",
    )
    parser.add_argument(
        "--out-dir",
        default="experiments_b_journal/audit_case/fashion_noniid_signflip_proposed_s42",
    )
    parser.add_argument("--tables-dir", default="experiments_b_journal/paper_tables")
    parser.add_argument("--results-dir", default="experiments_b_journal")
    parser.add_argument("--multi-run", action="store_true", help="Export metrics for all latest formal proposed runs.")
    args = parser.parse_args()

    if args.multi_run:
        run_dirs = discover_latest_runs(Path(args.results_dir))
        rows = [compute_run_metrics(run_dir) for run_dir in run_dirs]
        tables_dir = Path(args.tables_dir)
        out_dir = Path(args.out_dir)
        grouped = aggregate_rows(rows, ["suite", "dataset", "split", "attack_type"])
        ratio_grouped = aggregate_rows(rows, ["suite", "dataset", "split", "attack_type", "malicious_ratio"])
        overview = overview_rows(rows)
        write_dict_csv(tables_dir / "auditability_metrics_per_run.csv", rows)
        write_dict_csv(tables_dir / "auditability_metrics_by_condition.csv", grouped)
        write_dict_csv(tables_dir / "auditability_metrics_by_ratio.csv", ratio_grouped)
        write_dict_csv(tables_dir / "auditability_metrics_overview.csv", overview)
        write_latex_table(tables_dir / "auditability_metrics_main_latex.txt", grouped)
        out_dir.mkdir(parents=True, exist_ok=True)
        write_dict_csv(out_dir / "auditability_metrics_per_run.csv", rows)
        print(f"Wrote {len(rows)} per-run auditability records")
        print(f"Wrote {tables_dir / 'auditability_metrics_per_run.csv'}")
        print(f"Wrote {tables_dir / 'auditability_metrics_by_condition.csv'}")
        return

    run_dir = Path(args.run_dir)
    blocks = load_blocks(run_dir / "audit_chain.jsonl")
    chain_valid = verify_blocks(blocks)
    tampered, tamper_total, tamper_rate = tamper_detection_rate(blocks)
    reconstructed, decisions, reconstruction_rate = decision_reconstruction_rate(blocks)
    influence = influence_metrics(load_client_rows(run_dir / "client_round_metrics.csv"))
    detection = round_detection_metrics(run_dir / "metrics_round.csv")

    rows = [
        {
            "metric": "Stored audit blocks",
            "value": str(len(blocks)),
            "unit": "blocks",
            "definition": "Number of hash-linked round records in the audit case.",
        },
        {
            "metric": "Chain verification rate",
            "value": "100.00" if chain_valid else "0.00",
            "unit": "%",
            "definition": "Share of the recorded audit chain that passes hash and linkage verification.",
        },
        {
            "metric": "Tamper detection rate",
            "value": percent(tamper_rate),
            "unit": "%",
            "definition": f"Detected altered chains after one simulated metric modification per block ({tampered}/{tamper_total}).",
        },
        {
            "metric": "Decision reconstruction rate",
            "value": percent(reconstruction_rate),
            "unit": "%",
            "definition": f"Client-round decisions reproducible from stored decision fields ({reconstructed}/{decisions}).",
        },
        {
            "metric": "Malicious suppression rate",
            "value": percent(influence["malicious_suppression_rate"]),
            "unit": "%",
            "definition": "Malicious client-rounds receiving zero aggregation weight.",
        },
        {
            "metric": "Benign retention rate",
            "value": percent(influence["benign_retention_rate"]),
            "unit": "%",
            "definition": "Benign client-rounds retaining nonzero aggregation weight.",
        },
        {
            "metric": "Mean malicious weight",
            "value": f"{influence['malicious_mean_weight']:.4f}",
            "unit": "weight",
            "definition": "Average aggregation weight assigned to malicious clients.",
        },
        {
            "metric": "Mean benign weight",
            "value": f"{influence['benign_mean_weight']:.4f}",
            "unit": "weight",
            "definition": "Average aggregation weight assigned to benign clients.",
        },
        {
            "metric": "Benign--malicious weight gap",
            "value": f"{influence['weight_gap']:.4f}",
            "unit": "weight",
            "definition": "Difference between mean benign and malicious aggregation weights.",
        },
        {
            "metric": "Mean rejection precision",
            "value": percent(detection["mean_precision"]),
            "unit": "%",
            "definition": "Round-average precision when zero-weight decisions are compared with known attack labels.",
        },
        {
            "metric": "Mean rejection recall",
            "value": percent(detection["mean_recall"]),
            "unit": "%",
            "definition": "Round-average recall when zero-weight decisions are compared with known attack labels.",
        },
        {
            "metric": "Mean false rejection rate",
            "value": percent(detection["mean_false_rejection_rate"]),
            "unit": "%",
            "definition": "Round-average benign-client zero-weight rate under known labels.",
        },
    ]

    out_dir = Path(args.out_dir)
    tables_dir = Path(args.tables_dir)
    write_metrics_csv(out_dir / "auditability_metrics.csv", rows)
    write_metrics_csv(tables_dir / "auditability_metrics_table.csv", rows)
    print(f"Wrote {out_dir / 'auditability_metrics.csv'}")
    print(f"Wrote {tables_dir / 'auditability_metrics_table.csv'}")


if __name__ == "__main__":
    main()
