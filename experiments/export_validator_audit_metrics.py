"""Evaluate validator-backed audit finalization under server-side tampering."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import time
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.research.validator_audit import (
    GENESIS_HASH,
    ValidatorCommittee,
    build_proposed_block,
    make_aggregator_secrets,
    make_client_secrets,
    make_validators,
    select_aggregator,
    tamper_block,
)


TAMPER_SCENARIOS = [
    "score_tamper",
    "weight_tamper",
    "client_weight_tamper",
    "model_hash_tamper",
    "previous_hash_tamper",
    "omit_client",
    "fake_client",
    "client_signature_tamper",
    "payload_hash_tamper",
    "unauthorized_aggregator",
    "aggregator_signature_tamper",
    "aggregator_equivocation",
]


def load_blocks(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def discover_latest_proposed_runs(results_dir: Path) -> list[Path]:
    candidates: dict[str, tuple[str, Path]] = {}
    for run_dir in results_dir.iterdir():
        if not run_dir.is_dir():
            continue
        if not run_dir.name.startswith(("core_", "core_ratio_")):
            continue
        if "proposed" not in run_dir.name:
            continue
        required = ["config.json", "summary.json", "audit_chain.jsonl"]
        if not all((run_dir / name).exists() for name in required):
            continue
        with (run_dir / "config.json").open("r", encoding="utf-8") as handle:
            config = json.load(handle)
        experiment_name = str(config.get("experiment_name", run_dir.name))
        started_at = str(config.get("started_at", run_dir.name.rsplit("_", 1)[-1]))
        current = candidates.get(experiment_name)
        if current is None or started_at > current[0]:
            candidates[experiment_name] = (started_at, run_dir)
    return [item[1] for item in sorted(candidates.values(), key=lambda row: row[1].name)]


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def mean_std(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    if len(values) == 1:
        return values[0], 0.0
    return statistics.mean(values), statistics.stdev(values)


def infer_client_ids(blocks: list[dict[str, Any]]) -> list[int]:
    client_ids: set[int] = set()
    for block in blocks:
        for client in block.get("payload", {}).get("clients", []):
            client_ids.add(int(client["client_id"]))
    return sorted(client_ids)


def evaluate_run(
    run_dir: Path,
    validator_count: int,
    threshold: int,
    byzantine_validators: int,
    aggregator_count: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    blocks = load_blocks(run_dir / "audit_chain.jsonl")
    client_secrets = make_client_secrets(infer_client_ids(blocks))
    aggregator_ids = list(range(aggregator_count))
    aggregator_secrets = make_aggregator_secrets(aggregator_ids)
    committee = ValidatorCommittee(make_validators(validator_count, byzantine_validators), threshold)

    valid_finalized = 0
    valid_total = 0
    valid_latencies: list[float] = []
    aggregator_authorization_checked = 0
    tamper_rows: list[dict[str, Any]] = []
    scenario_counts = {
        scenario: {"rejected": 0, "accepted": 0, "total": 0, "latencies": []}
        for scenario in TAMPER_SCENARIOS
    }

    previous_hash = GENESIS_HASH
    for block in blocks:
        aggregator_id = select_aggregator(int(block["round"]), aggregator_ids)
        proposed = build_proposed_block(
            block,
            previous_hash,
            client_secrets,
            aggregator_id=aggregator_id,
            aggregator_secret=aggregator_secrets[aggregator_id],
        )
        start = time.perf_counter()
        finalized = committee.finalize(
            proposed,
            previous_hash,
            client_secrets,
            aggregator_ids=aggregator_ids,
            aggregator_secrets=aggregator_secrets,
        )
        elapsed = time.perf_counter() - start
        valid_total += 1
        aggregator_authorization_checked += int(finalized.finalized)
        valid_latencies.append(elapsed)
        if finalized.finalized:
            valid_finalized += 1

        for scenario in TAMPER_SCENARIOS:
            bad = tamper_block(proposed, scenario)
            start = time.perf_counter()
            bad_finalized = committee.finalize(
                bad,
                previous_hash,
                client_secrets,
                aggregator_ids=aggregator_ids,
                aggregator_secrets=aggregator_secrets,
            )
            elapsed = time.perf_counter() - start
            bucket = scenario_counts[scenario]
            bucket["total"] += 1
            bucket["latencies"].append(elapsed)
            if bad_finalized.finalized:
                bucket["accepted"] += 1
            else:
                bucket["rejected"] += 1

        previous_hash = finalized.block_hash if finalized.finalized else previous_hash

    with (run_dir / "config.json").open("r", encoding="utf-8") as handle:
        config = json.load(handle)
    metadata = {
        "run": run_dir.name,
        "experiment_name": str(config.get("experiment_name", run_dir.name)),
        "dataset": str(config.get("dataset", "")),
        "split": "IID" if bool(config.get("iid")) else "Non-IID",
        "attack_type": str(config.get("attack_type", "")),
        "seed": int(config.get("seed", -1)),
        "rounds": len(blocks),
        "validator_count": validator_count,
        "threshold": threshold,
        "byzantine_validators": byzantine_validators,
        "aggregator_count": aggregator_count,
        "valid_block_finalization_rate": valid_finalized / valid_total if valid_total else 0.0,
        "aggregator_authorization_verification_rate": (
            aggregator_authorization_checked / valid_total if valid_total else 0.0
        ),
        "mean_valid_verification_time_ms": 1000.0 * statistics.mean(valid_latencies) if valid_latencies else 0.0,
    }

    for scenario, counts in scenario_counts.items():
        total = counts["total"]
        latencies = counts["latencies"]
        tamper_rows.append(
            {
                **metadata,
                "scenario": scenario,
                "invalid_block_rejection_rate": counts["rejected"] / total if total else 0.0,
                "invalid_block_acceptance_rate": counts["accepted"] / total if total else 0.0,
                "tampered_blocks": total,
                "mean_invalid_verification_time_ms": 1000.0 * statistics.mean(latencies) if latencies else 0.0,
            }
        )

    return tamper_rows, metadata


def aggregate_by_scenario(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(str(row["scenario"]), []).append(row)
    output = []
    for scenario, group in sorted(groups.items()):
        rejection_values = [float(row["invalid_block_rejection_rate"]) for row in group]
        acceptance_values = [float(row["invalid_block_acceptance_rate"]) for row in group]
        valid_values = [float(row["valid_block_finalization_rate"]) for row in group]
        authorization_values = [float(row["aggregator_authorization_verification_rate"]) for row in group]
        invalid_time = [float(row["mean_invalid_verification_time_ms"]) for row in group]
        valid_time = [float(row["mean_valid_verification_time_ms"]) for row in group]
        rej_mean, rej_std = mean_std(rejection_values)
        acc_mean, acc_std = mean_std(acceptance_values)
        valid_mean, valid_std = mean_std(valid_values)
        auth_mean, auth_std = mean_std(authorization_values)
        invalid_ms, invalid_ms_std = mean_std(invalid_time)
        valid_ms, valid_ms_std = mean_std(valid_time)
        output.append(
            {
                "scenario": scenario,
                "runs": len(group),
                "tampered_blocks": sum(int(row["tampered_blocks"]) for row in group),
                "valid_block_finalization_rate_mean": valid_mean,
                "valid_block_finalization_rate_std": valid_std,
                "aggregator_authorization_verification_rate_mean": auth_mean,
                "aggregator_authorization_verification_rate_std": auth_std,
                "invalid_block_rejection_rate_mean": rej_mean,
                "invalid_block_rejection_rate_std": rej_std,
                "invalid_block_acceptance_rate_mean": acc_mean,
                "invalid_block_acceptance_rate_std": acc_std,
                "mean_valid_verification_time_ms": valid_ms,
                "std_valid_verification_time_ms": valid_ms_std,
                "mean_invalid_verification_time_ms": invalid_ms,
                "std_invalid_verification_time_ms": invalid_ms_std,
            }
        )
    return output


def threshold_sensitivity(
    run_dirs: list[Path],
    settings: list[tuple[int, int, int]],
    aggregator_count: int,
) -> list[dict[str, Any]]:
    rows = []
    for validator_count, threshold, byzantine in settings:
        setting_rows = []
        for run_dir in run_dirs:
            tamper_rows, metadata = evaluate_run(
                run_dir,
                validator_count,
                threshold,
                byzantine,
                aggregator_count=aggregator_count,
            )
            rejection_values = [float(row["invalid_block_rejection_rate"]) for row in tamper_rows]
            setting_rows.append(
                {
                    "valid": metadata["valid_block_finalization_rate"],
                    "rejection": statistics.mean(rejection_values) if rejection_values else 0.0,
                    "time": metadata["mean_valid_verification_time_ms"],
                }
            )
        valid_mean, valid_std = mean_std([row["valid"] for row in setting_rows])
        rejection_mean, rejection_std = mean_std([row["rejection"] for row in setting_rows])
        time_mean, time_std = mean_std([row["time"] for row in setting_rows])
        rows.append(
            {
                "validator_count": validator_count,
                "threshold": threshold,
                "byzantine_validators": byzantine,
                "runs": len(setting_rows),
                "valid_block_finalization_rate_mean": valid_mean,
                "valid_block_finalization_rate_std": valid_std,
                "invalid_block_rejection_rate_mean": rejection_mean,
                "invalid_block_rejection_rate_std": rejection_std,
                "mean_valid_verification_time_ms": time_mean,
                "std_valid_verification_time_ms": time_std,
            }
        )
    return rows


def byzantine_boundary_sensitivity(
    run_dirs: list[Path],
    settings: list[tuple[int, int, int, str]],
    aggregator_count: int,
) -> list[dict[str, Any]]:
    """Evaluate when invalid proposals become finalizable under validator collusion."""

    rows = []
    for validator_count, threshold, byzantine, assumption_status in settings:
        setting_rows = []
        for run_dir in run_dirs:
            tamper_rows, metadata = evaluate_run(
                run_dir,
                validator_count,
                threshold,
                byzantine,
                aggregator_count=aggregator_count,
            )
            acceptance_values = [float(row["invalid_block_acceptance_rate"]) for row in tamper_rows]
            rejection_values = [float(row["invalid_block_rejection_rate"]) for row in tamper_rows]
            setting_rows.append(
                {
                    "valid": metadata["valid_block_finalization_rate"],
                    "acceptance": statistics.mean(acceptance_values) if acceptance_values else 0.0,
                    "rejection": statistics.mean(rejection_values) if rejection_values else 0.0,
                    "time": metadata["mean_valid_verification_time_ms"],
                }
            )
        valid_mean, valid_std = mean_std([row["valid"] for row in setting_rows])
        acceptance_mean, acceptance_std = mean_std([row["acceptance"] for row in setting_rows])
        rejection_mean, rejection_std = mean_std([row["rejection"] for row in setting_rows])
        time_mean, time_std = mean_std([row["time"] for row in setting_rows])
        rows.append(
            {
                "validator_count": validator_count,
                "threshold": threshold,
                "byzantine_validators": byzantine,
                "assumption_status": assumption_status,
                "runs": len(setting_rows),
                "valid_block_finalization_rate_mean": valid_mean,
                "valid_block_finalization_rate_std": valid_std,
                "invalid_block_rejection_rate_mean": rejection_mean,
                "invalid_block_rejection_rate_std": rejection_std,
                "invalid_block_acceptance_rate_mean": acceptance_mean,
                "invalid_block_acceptance_rate_std": acceptance_std,
                "mean_valid_verification_time_ms": time_mean,
                "std_valid_verification_time_ms": time_std,
            }
        )
    return rows


def representative_runs(run_dirs: list[Path]) -> list[Path]:
    """Pick one latest run per suite/dataset/split/attack setting for threshold sweeps."""

    selected: dict[tuple[str, str, str, str], Path] = {}
    for run_dir in run_dirs:
        with (run_dir / "config.json").open("r", encoding="utf-8") as handle:
            config = json.load(handle)
        suite = "ratio" if str(config.get("experiment_name", "")).startswith("core_ratio_") else "main"
        key = (
            suite,
            str(config.get("dataset", "")),
            "IID" if bool(config.get("iid")) else "Non-IID",
            str(config.get("attack_type", "")),
        )
        current = selected.get(key)
        if current is None or run_dir.name > current.name:
            selected[key] = run_dir
    return [selected[key] for key in sorted(selected)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", default="experiments_b_journal")
    parser.add_argument("--out-dir", default="experiments_b_journal/paper_tables")
    parser.add_argument("--validator-count", type=int, default=5)
    parser.add_argument("--threshold", type=int, default=3)
    parser.add_argument("--byzantine-validators", type=int, default=0)
    parser.add_argument("--aggregator-count", type=int, default=5)
    args = parser.parse_args()

    run_dirs = discover_latest_proposed_runs(Path(args.results_dir))
    all_tamper_rows: list[dict[str, Any]] = []
    valid_rows: list[dict[str, Any]] = []
    for run_dir in run_dirs:
        rows, metadata = evaluate_run(
            run_dir,
            validator_count=args.validator_count,
            threshold=args.threshold,
            byzantine_validators=args.byzantine_validators,
            aggregator_count=args.aggregator_count,
        )
        all_tamper_rows.extend(rows)
        valid_rows.append(metadata)

    out_dir = Path(args.out_dir)
    write_csv(out_dir / "validator_audit_tamper_per_run.csv", all_tamper_rows)
    write_csv(out_dir / "validator_audit_tamper_by_scenario.csv", aggregate_by_scenario(all_tamper_rows))
    write_csv(out_dir / "validator_audit_valid_blocks.csv", valid_rows)

    settings = [
        (3, 2, 0),
        (5, 3, 0),
        (7, 4, 0),
        (5, 3, 1),
        (7, 5, 2),
    ]
    threshold_runs = representative_runs(run_dirs)
    write_csv(
        out_dir / "validator_audit_threshold_sensitivity.csv",
        threshold_sensitivity(threshold_runs, settings, aggregator_count=args.aggregator_count),
    )
    boundary_settings = [
        (5, 3, 0, "honest_committee"),
        (5, 3, 1, "within_assumption"),
        (5, 3, 2, "within_assumption"),
        (5, 3, 3, "assumption_violated"),
        (7, 5, 2, "within_assumption"),
        (7, 5, 4, "within_assumption"),
        (7, 5, 5, "assumption_violated"),
    ]
    write_csv(
        out_dir / "validator_audit_byzantine_boundary.csv",
        byzantine_boundary_sensitivity(
            threshold_runs,
            boundary_settings,
            aggregator_count=args.aggregator_count,
        ),
    )

    print(f"Evaluated validator-backed audit on {len(run_dirs)} runs")
    print(f"Evaluated threshold sensitivity on {len(threshold_runs)} representative runs")
    print(f"Wrote tables to {out_dir}")


if __name__ == "__main__":
    main()
