"""Export quantitative auditability metrics from a recorded audit case."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
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
    args = parser.parse_args()

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
