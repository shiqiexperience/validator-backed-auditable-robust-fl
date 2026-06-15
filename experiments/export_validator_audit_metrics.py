"""Evaluate validator-backed audit finalization under server-side tampering."""

from __future__ import annotations

import argparse
import csv
import json
import random
import statistics
import time
from pathlib import Path
import sys
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.research.validator_audit import (
    GENESIS_HASH,
    ValidatorCommittee,
    build_proposed_block,
    canonical_json,
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
    "evidence_hash_tamper",
    "missing_evidence",
    "unauthorized_aggregator",
    "aggregator_signature_tamper",
    "aggregator_equivocation",
    "self_consistent_score_tamper",
    "self_consistent_weight_tamper",
    "evidence_score_tamper",
]

SELF_CONSISTENT_SCENARIOS = {
    "evidence_hash_tamper",
    "missing_evidence",
    "self_consistent_score_tamper",
    "self_consistent_weight_tamper",
    "evidence_score_tamper",
}


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


def json_size_bytes(payload: Mapping[str, Any]) -> int:
    return len(canonical_json(payload).encode("utf-8"))


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


def expand_block_clients(source_block: Mapping[str, Any], target_clients: int) -> dict[str, Any]:
    """Create a deterministic synthetic block with more client evidence rows.

    The scalability experiment measures protocol-verification cost rather than
    model utility. It therefore reuses recorded per-client evidence patterns and
    assigns fresh client ids so validators still verify commitments, hashes, and
    decision consistency for the requested client count.
    """

    block = json.loads(json.dumps(source_block))
    payload = block.get("payload", {})
    clients = list(payload.get("clients", []))
    decisions = list(payload.get("decisions", []))
    if not clients or not decisions:
        raise ValueError("source block must contain clients and decisions")

    client_by_id = {int(client["client_id"]): client for client in clients}
    decision_by_id = {int(float(decision["client_id"])): decision for decision in decisions}
    base_ids = [client_id for client_id in sorted(client_by_id) if client_id in decision_by_id]
    if not base_ids:
        raise ValueError("source block must contain matching clients and decisions")

    expanded_clients = []
    expanded_decisions = []
    for new_id in range(int(target_clients)):
        template_id = base_ids[new_id % len(base_ids)]
        client = dict(client_by_id[template_id])
        decision = dict(decision_by_id[template_id])
        client["client_id"] = new_id
        decision["client_id"] = float(new_id)
        expanded_clients.append(client)
        expanded_decisions.append(decision)

    payload["clients"] = expanded_clients
    payload["decisions"] = expanded_decisions
    block["payload"] = payload
    return block


def evaluate_run(
    run_dir: Path,
    validator_count: int,
    threshold: int,
    byzantine_validators: int,
    aggregator_count: int,
    offline_validators: int = 0,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    blocks = load_blocks(run_dir / "audit_chain.jsonl")
    client_secrets = make_client_secrets(infer_client_ids(blocks))
    aggregator_ids = list(range(aggregator_count))
    aggregator_secrets = make_aggregator_secrets(aggregator_ids)
    committee = ValidatorCommittee(
        make_validators(
            validator_count,
            byzantine_validators,
            offline_count=offline_validators,
        ),
        threshold,
    )

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
            bad = tamper_block(
                proposed,
                scenario,
                aggregator_secret=aggregator_secrets[aggregator_id],
            )
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
        "offline_validators": offline_validators,
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


def summarize_self_consistent_tamper(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary_rows = [
        row
        for row in aggregate_by_scenario(rows)
        if str(row["scenario"]) in SELF_CONSISTENT_SCENARIOS
    ]
    for row in summary_rows:
        scenario = str(row["scenario"])
        if scenario in {"self_consistent_score_tamper", "self_consistent_weight_tamper"}:
            row["verification_target"] = "decision_recomputation_after_refreshed_hashes"
        elif scenario == "evidence_score_tamper":
            row["verification_target"] = "evidence_bound_decision_recomputation"
        elif scenario == "missing_evidence":
            row["verification_target"] = "evidence_availability"
        else:
            row["verification_target"] = "evidence_hash_integrity"
    return summary_rows


def evaluate_tamper_section(
    run_dirs: list[Path],
    out_dir: Path,
    validator_count: int,
    threshold: int,
    byzantine_validators: int,
    aggregator_count: int,
) -> None:
    all_tamper_rows: list[dict[str, Any]] = []
    valid_rows: list[dict[str, Any]] = []
    for run_dir in run_dirs:
        rows, metadata = evaluate_run(
            run_dir,
            validator_count=validator_count,
            threshold=threshold,
            byzantine_validators=byzantine_validators,
            aggregator_count=aggregator_count,
        )
        all_tamper_rows.extend(rows)
        valid_rows.append(metadata)

    write_csv(out_dir / "validator_audit_tamper_per_run.csv", all_tamper_rows)
    write_csv(out_dir / "validator_audit_tamper_by_scenario.csv", aggregate_by_scenario(all_tamper_rows))
    write_csv(out_dir / "validator_audit_self_consistent_tamper.csv", summarize_self_consistent_tamper(all_tamper_rows))
    write_csv(out_dir / "validator_audit_valid_blocks.csv", valid_rows)


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


def liveness_dropout_sensitivity(
    run_dirs: list[Path],
    settings: list[tuple[int, int, int, int]],
    aggregator_count: int,
) -> list[dict[str, Any]]:
    """Evaluate valid-block finalization when validators are offline."""

    rows = []
    for validator_count, threshold, byzantine, offline in settings:
        setting_rows = []
        for run_dir in run_dirs:
            tamper_rows, metadata = evaluate_run(
                run_dir,
                validator_count,
                threshold,
                byzantine,
                aggregator_count=aggregator_count,
                offline_validators=offline,
            )
            rejection_values = [float(row["invalid_block_rejection_rate"]) for row in tamper_rows]
            acceptance_values = [float(row["invalid_block_acceptance_rate"]) for row in tamper_rows]
            setting_rows.append(
                {
                    "valid": metadata["valid_block_finalization_rate"],
                    "rejection": statistics.mean(rejection_values) if rejection_values else 0.0,
                    "acceptance": statistics.mean(acceptance_values) if acceptance_values else 0.0,
                    "time": metadata["mean_valid_verification_time_ms"],
                }
            )
        valid_mean, valid_std = mean_std([row["valid"] for row in setting_rows])
        rejection_mean, rejection_std = mean_std([row["rejection"] for row in setting_rows])
        acceptance_mean, acceptance_std = mean_std([row["acceptance"] for row in setting_rows])
        time_mean, time_std = mean_std([row["time"] for row in setting_rows])
        rows.append(
            {
                "validator_count": validator_count,
                "threshold": threshold,
                "byzantine_validators": byzantine,
                "offline_validators": offline,
                "available_validators": validator_count - offline,
                "runs": len(setting_rows),
                "valid_block_finalization_rate_mean": valid_mean,
                "valid_block_finalization_rate_std": valid_std,
                "valid_block_failure_rate_mean": 1.0 - valid_mean,
                "invalid_block_rejection_rate_mean": rejection_mean,
                "invalid_block_rejection_rate_std": rejection_std,
                "invalid_block_acceptance_rate_mean": acceptance_mean,
                "invalid_block_acceptance_rate_std": acceptance_std,
                "mean_valid_verification_time_ms": time_mean,
                "std_valid_verification_time_ms": time_std,
            }
        )
    return rows


def validator_accountability_sensitivity(
    run_dirs: list[Path],
    settings: list[tuple[int, int, int, str]],
    aggregator_count: int,
) -> list[dict[str, Any]]:
    """Measure whether invalid-signing validators are identifiable and slashable."""

    rows = []
    for validator_count, threshold, byzantine, assumption_status in settings:
        invalid_proposals = 0
        invalid_signatures = 0
        per_validator_invalid: dict[int, int] = {idx: 0 for idx in range(validator_count)}
        finalized_invalid = 0
        for run_dir in run_dirs:
            blocks = load_blocks(run_dir / "audit_chain.jsonl")
            client_secrets = make_client_secrets(infer_client_ids(blocks))
            aggregator_ids = list(range(aggregator_count))
            aggregator_secrets = make_aggregator_secrets(aggregator_ids)
            committee = ValidatorCommittee(
                make_validators(validator_count, byzantine),
                threshold,
            )
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
                valid_finalized = committee.finalize(
                    proposed,
                    previous_hash,
                    client_secrets,
                    aggregator_ids=aggregator_ids,
                    aggregator_secrets=aggregator_secrets,
                )
                for scenario in TAMPER_SCENARIOS:
                    invalid_proposals += 1
                    bad = tamper_block(
                        proposed,
                        scenario,
                        aggregator_secret=aggregator_secrets[aggregator_id],
                    )
                    bad_finalized = committee.finalize(
                        bad,
                        previous_hash,
                        client_secrets,
                        aggregator_ids=aggregator_ids,
                        aggregator_secrets=aggregator_secrets,
                    )
                    if bad_finalized.finalized:
                        finalized_invalid += 1
                    for vote in bad_finalized.validator_signatures:
                        validator_id = int(vote["validator_id"])
                        invalid_signatures += 1
                        per_validator_invalid[validator_id] += 1
                previous_hash = valid_finalized.block_hash if valid_finalized.finalized else previous_hash

        slashable = [validator_id for validator_id, count in per_validator_invalid.items() if count > 0]
        rows.append(
            {
                "validator_count": validator_count,
                "threshold": threshold,
                "byzantine_validators": byzantine,
                "assumption_status": assumption_status,
                "runs": len(run_dirs),
                "invalid_proposals": invalid_proposals,
                "invalid_signatures": invalid_signatures,
                "invalid_signing_rate": invalid_signatures / max(invalid_proposals * validator_count, 1),
                "invalid_finalization_rate": finalized_invalid / max(invalid_proposals, 1),
                "slashable_validator_count": len(slashable),
                "slashable_validators": " ".join(str(validator_id) for validator_id in slashable),
            }
        )
    return rows


def validator_scalability_sweep(
    run_dirs: list[Path],
    client_counts: list[int],
    committee_settings: list[tuple[int, int]],
    aggregator_count: int,
    max_runs: int,
    max_blocks_per_run: int,
) -> list[dict[str, Any]]:
    """Measure validator-layer scaling with client and committee counts."""

    rows: list[dict[str, Any]] = []
    selected_runs = run_dirs[: max(1, max_runs)]
    for target_clients in client_counts:
        for validator_count, threshold in committee_settings:
            valid_latencies: list[float] = []
            invalid_latencies: list[float] = []
            proposal_sizes: list[int] = []
            evidence_sizes: list[int] = []
            payload_sizes: list[int] = []
            commitment_sizes: list[int] = []
            finalized_sizes: list[int] = []
            valid_finalized = 0
            valid_total = 0
            invalid_rejected = 0
            invalid_total = 0
            for run_dir in selected_runs:
                blocks = load_blocks(run_dir / "audit_chain.jsonl")[: max(1, max_blocks_per_run)]
                client_secrets = make_client_secrets(range(target_clients))
                aggregator_ids = list(range(aggregator_count))
                aggregator_secrets = make_aggregator_secrets(aggregator_ids)
                committee = ValidatorCommittee(
                    make_validators(validator_count, byzantine_count=0),
                    threshold,
                )
                previous_hash = GENESIS_HASH
                for block in blocks:
                    expanded = expand_block_clients(block, target_clients)
                    aggregator_id = select_aggregator(int(block["round"]), aggregator_ids)
                    proposed = build_proposed_block(
                        expanded,
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
                    valid_elapsed = time.perf_counter() - start
                    valid_total += 1
                    valid_latencies.append(valid_elapsed)
                    proposal_sizes.append(json_size_bytes(proposed))
                    payload_sizes.append(json_size_bytes(proposed["payload"]))
                    evidence_sizes.append(json_size_bytes(proposed["evidence"]))
                    commitment_sizes.append(json_size_bytes({"client_commitments": proposed["client_commitments"]}))
                    finalized_sizes.append(json_size_bytes(finalized.to_record()))
                    if finalized.finalized:
                        valid_finalized += 1

                    bad = tamper_block(
                        proposed,
                        "self_consistent_weight_tamper",
                        aggregator_secret=aggregator_secrets[aggregator_id],
                    )
                    start = time.perf_counter()
                    bad_finalized = committee.finalize(
                        bad,
                        previous_hash,
                        client_secrets,
                        aggregator_ids=aggregator_ids,
                        aggregator_secrets=aggregator_secrets,
                    )
                    invalid_elapsed = time.perf_counter() - start
                    invalid_total += 1
                    invalid_latencies.append(invalid_elapsed)
                    if not bad_finalized.finalized:
                        invalid_rejected += 1
                    previous_hash = finalized.block_hash if finalized.finalized else previous_hash

            valid_ms, valid_ms_std = mean_std([1000.0 * value for value in valid_latencies])
            invalid_ms, invalid_ms_std = mean_std([1000.0 * value for value in invalid_latencies])
            proposal_bytes, proposal_bytes_std = mean_std([float(value) for value in proposal_sizes])
            evidence_bytes, evidence_bytes_std = mean_std([float(value) for value in evidence_sizes])
            payload_bytes, _ = mean_std([float(value) for value in payload_sizes])
            commitment_bytes, _ = mean_std([float(value) for value in commitment_sizes])
            finalized_bytes, finalized_bytes_std = mean_std([float(value) for value in finalized_sizes])
            rows.append(
                {
                    "synthetic_clients": target_clients,
                    "validator_count": validator_count,
                    "threshold": threshold,
                    "runs": len(selected_runs),
                    "blocks": valid_total,
                    "valid_block_finalization_rate": valid_finalized / valid_total if valid_total else 0.0,
                    "invalid_block_rejection_rate": invalid_rejected / invalid_total if invalid_total else 0.0,
                    "mean_valid_verification_time_ms": valid_ms,
                    "std_valid_verification_time_ms": valid_ms_std,
                    "mean_invalid_verification_time_ms": invalid_ms,
                    "std_invalid_verification_time_ms": invalid_ms_std,
                    "mean_proposal_bytes": proposal_bytes,
                    "std_proposal_bytes": proposal_bytes_std,
                    "mean_payload_bytes": payload_bytes,
                    "mean_evidence_bytes": evidence_bytes,
                    "std_evidence_bytes": evidence_bytes_std,
                    "mean_commitment_bytes": commitment_bytes,
                    "mean_finalized_record_bytes": finalized_bytes,
                    "std_finalized_record_bytes": finalized_bytes_std,
                    "aggregator_to_committee_bytes_per_round": proposal_bytes * validator_count,
                    "threshold_signature_record_bytes": finalized_bytes,
                }
            )
    return rows


def read_csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def network_latency_sensitivity(
    scalability_rows: list[dict[str, str]],
    bandwidth_mbps_values: list[float],
    rtt_ms_values: list[float],
) -> list[dict[str, Any]]:
    """Estimate two-phase finality latency under bandwidth and RTT settings.

    The model approximates one aggregator-to-validator proposal phase followed
    by one validator-to-aggregator vote/finality phase. It uses measured local
    verification time and measured serialized proposal/finality record sizes.
    """

    rows: list[dict[str, Any]] = []
    for source in scalability_rows:
        clients = int(float(source["synthetic_clients"]))
        validators = int(float(source["validator_count"]))
        threshold = int(float(source["threshold"]))
        proposal_bytes = float(source["mean_proposal_bytes"])
        finalized_bytes = float(source["mean_finalized_record_bytes"])
        verification_ms = float(source["mean_valid_verification_time_ms"])
        for bandwidth_mbps in bandwidth_mbps_values:
            bytes_per_ms = bandwidth_mbps * 1_000_000.0 / 8.0 / 1000.0
            proposal_tx_ms = proposal_bytes / bytes_per_ms
            vote_tx_ms = finalized_bytes / bytes_per_ms
            for rtt_ms in rtt_ms_values:
                network_ms = 2.0 * rtt_ms + proposal_tx_ms + vote_tx_ms
                finality_ms = network_ms + verification_ms
                rows.append(
                    {
                        "synthetic_clients": clients,
                        "validator_count": validators,
                        "threshold": threshold,
                        "bandwidth_mbps": bandwidth_mbps,
                        "rtt_ms": rtt_ms,
                        "proposal_kb": proposal_bytes / 1024.0,
                        "finality_record_kb": finalized_bytes / 1024.0,
                        "proposal_tx_ms": proposal_tx_ms,
                        "vote_tx_ms": vote_tx_ms,
                        "network_ms": network_ms,
                        "verification_ms": verification_ms,
                        "estimated_finality_ms": finality_ms,
                    }
                )
    return rows


def summarize_network_latency(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected = []
    wanted = {
        (10, 5, 3, 100.0, 10.0),
        (100, 5, 3, 100.0, 10.0),
        (200, 5, 3, 100.0, 10.0),
        (100, 5, 3, 10.0, 50.0),
        (200, 5, 3, 10.0, 50.0),
        (100, 11, 7, 100.0, 10.0),
        (100, 11, 7, 10.0, 50.0),
        (200, 11, 7, 10.0, 100.0),
    }
    for row in rows:
        key = (
            int(row["synthetic_clients"]),
            int(row["validator_count"]),
            int(row["threshold"]),
            float(row["bandwidth_mbps"]),
            float(row["rtt_ms"]),
        )
        if key in wanted:
            selected.append(row)
    return sorted(
        selected,
        key=lambda row: (
            int(row["synthetic_clients"]),
            int(row["validator_count"]),
            float(row["bandwidth_mbps"]),
            float(row["rtt_ms"]),
        ),
    )


def quantile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * q))))
    return ordered[index]


def event_driven_finality_simulation(
    scalability_rows: list[dict[str, str]],
    bandwidth_mbps_values: list[float],
    rtt_ms_values: list[float],
    dropout_rates: list[float],
    trial_count: int = 500,
    timeout_ms: float = 2_000.0,
    seed: int = 20260615,
) -> list[dict[str, Any]]:
    """Simulate proposal, verification, vote, finality, and timeout events.

    This is an application-layer finality simulation, not a full PBFT/HotStuff
    network. It reuses measured proposal sizes and verification costs, then
    models one proposal broadcast and one vote-return phase with deterministic
    pseudo-random jitter and validator dropout.
    """

    rows: list[dict[str, Any]] = []
    proposal_types = ["valid", "invalid"]
    selected_clients = {10, 100, 200}
    selected_committees = {(5, 3), (11, 7)}
    for source in scalability_rows:
        clients = int(float(source["synthetic_clients"]))
        validators = int(float(source["validator_count"]))
        threshold = int(float(source["threshold"]))
        if clients not in selected_clients or (validators, threshold) not in selected_committees:
            continue

        proposal_bytes = float(source["mean_proposal_bytes"])
        finalized_bytes = float(source["mean_finalized_record_bytes"])
        committee_verification_ms = float(source["mean_valid_verification_time_ms"])
        per_validator_verification_ms = committee_verification_ms / max(validators, 1)
        vote_bytes = max(256.0, finalized_bytes / max(threshold, 1))
        byzantine_settings = sorted({0, max(threshold - 1, 0), threshold})

        for bandwidth_mbps in bandwidth_mbps_values:
            bytes_per_ms = bandwidth_mbps * 1_000_000.0 / 8.0 / 1000.0
            proposal_tx_ms = proposal_bytes / bytes_per_ms
            vote_tx_ms = vote_bytes / bytes_per_ms
            for rtt_ms in rtt_ms_values:
                one_way_ms = rtt_ms / 2.0
                for dropout_rate in dropout_rates:
                    for byzantine_validators in byzantine_settings:
                        byzantine_validators = min(byzantine_validators, validators)
                        for proposal_type in proposal_types:
                            rng = random.Random(
                                f"{seed}:{clients}:{validators}:{threshold}:"
                                f"{bandwidth_mbps}:{rtt_ms}:{dropout_rate}:"
                                f"{byzantine_validators}:{proposal_type}"
                            )
                            finalized_count = 0
                            rejected_count = 0
                            invalid_accepted_count = 0
                            timeout_count = 0
                            latencies: list[float] = []
                            message_counts: list[int] = []
                            bytes_counts: list[float] = []
                            available_counts: list[int] = []

                            for _ in range(trial_count):
                                accept_arrivals: list[float] = []
                                reject_arrivals: list[float] = []
                                online_validators = 0
                                for validator_id in range(validators):
                                    if rng.random() < dropout_rate:
                                        continue
                                    online_validators += 1
                                    is_byzantine = validator_id < byzantine_validators
                                    jitter = rng.uniform(0.85, 1.15)
                                    propagation_jitter = rng.uniform(0.8, 1.2)
                                    arrival_ms = (
                                        one_way_ms * propagation_jitter
                                        + proposal_tx_ms
                                        + per_validator_verification_ms * jitter
                                        + one_way_ms * propagation_jitter
                                        + vote_tx_ms
                                    )
                                    if proposal_type == "valid" or is_byzantine:
                                        accept_arrivals.append(arrival_ms)
                                    else:
                                        reject_arrivals.append(arrival_ms)

                                accept_arrivals.sort()
                                reject_arrivals.sort()
                                accept_time = (
                                    accept_arrivals[threshold - 1]
                                    if len(accept_arrivals) >= threshold
                                    else None
                                )
                                reject_time = (
                                    reject_arrivals[threshold - 1]
                                    if len(reject_arrivals) >= threshold
                                    else None
                                )
                                event_time = min(
                                    [value for value in [accept_time, reject_time] if value is not None],
                                    default=None,
                                )
                                if event_time is None or event_time > timeout_ms:
                                    timeout_count += 1
                                    latencies.append(timeout_ms)
                                elif proposal_type == "valid":
                                    finalized_count += 1
                                    latencies.append(event_time)
                                elif accept_time is not None and accept_time == event_time:
                                    invalid_accepted_count += 1
                                    latencies.append(event_time)
                                else:
                                    rejected_count += 1
                                    latencies.append(event_time)

                                message_counts.append(1 + online_validators)
                                bytes_counts.append(proposal_bytes * online_validators + vote_bytes * online_validators)
                                available_counts.append(online_validators)

                            rows.append(
                                {
                                    "synthetic_clients": clients,
                                    "validator_count": validators,
                                    "threshold": threshold,
                                    "proposal_type": proposal_type,
                                    "byzantine_validators": byzantine_validators,
                                    "dropout_rate": dropout_rate,
                                    "bandwidth_mbps": bandwidth_mbps,
                                    "rtt_ms": rtt_ms,
                                    "trials": trial_count,
                                    "valid_finalization_rate": finalized_count / trial_count,
                                    "invalid_rejection_rate": rejected_count / trial_count,
                                    "invalid_acceptance_rate": invalid_accepted_count / trial_count,
                                    "timeout_rate": timeout_count / trial_count,
                                    "mean_finality_ms": statistics.mean(latencies),
                                    "p95_finality_ms": quantile(latencies, 0.95),
                                    "mean_available_validators": statistics.mean(available_counts),
                                    "mean_messages_per_round": statistics.mean(message_counts),
                                    "mean_committee_kb_per_round": statistics.mean(bytes_counts) / 1024.0,
                                }
                            )
    return rows


def summarize_event_driven_finality(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    wanted = {
        (100, 5, 3, "valid", 0, 0.0, 100.0, 10.0),
        (200, 5, 3, "valid", 0, 0.0, 100.0, 10.0),
        (200, 5, 3, "valid", 0, 0.2, 100.0, 10.0),
        (200, 5, 3, "invalid", 2, 0.0, 100.0, 10.0),
        (200, 5, 3, "invalid", 3, 0.0, 100.0, 10.0),
        (200, 11, 7, "valid", 0, 0.0, 10.0, 100.0),
        (200, 11, 7, "invalid", 6, 0.0, 10.0, 100.0),
        (200, 11, 7, "invalid", 7, 0.0, 10.0, 100.0),
    }
    selected = []
    for row in rows:
        key = (
            int(row["synthetic_clients"]),
            int(row["validator_count"]),
            int(row["threshold"]),
            str(row["proposal_type"]),
            int(row["byzantine_validators"]),
            float(row["dropout_rate"]),
            float(row["bandwidth_mbps"]),
            float(row["rtt_ms"]),
        )
        if key in wanted:
            selected.append(row)
    return sorted(
        selected,
        key=lambda row: (
            int(row["synthetic_clients"]),
            int(row["validator_count"]),
            str(row["proposal_type"]),
            int(row["byzantine_validators"]),
            float(row["dropout_rate"]),
            float(row["bandwidth_mbps"]),
            float(row["rtt_ms"]),
        ),
    )


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
    parser.add_argument(
        "--section",
        choices=[
            "all",
            "tamper",
            "threshold",
            "boundary",
            "liveness",
            "accountability",
            "scalability",
            "network_latency",
            "network_events",
        ],
        default="all",
        help="Select which validator-audit table group to export.",
    )
    parser.add_argument("--scalability-max-runs", type=int, default=5)
    parser.add_argument("--scalability-max-blocks-per-run", type=int, default=10)
    args = parser.parse_args()

    run_dirs = discover_latest_proposed_runs(Path(args.results_dir))
    out_dir = Path(args.out_dir)
    if args.section in {"all", "tamper"}:
        evaluate_tamper_section(
            run_dirs,
            out_dir,
            validator_count=args.validator_count,
            threshold=args.threshold,
            byzantine_validators=args.byzantine_validators,
            aggregator_count=args.aggregator_count,
        )

    settings = [
        (3, 2, 0),
        (5, 3, 0),
        (7, 4, 0),
        (5, 3, 1),
        (7, 5, 2),
    ]
    threshold_runs = representative_runs(run_dirs)
    if args.section in {"all", "threshold"}:
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
    if args.section in {"all", "boundary"}:
        write_csv(
            out_dir / "validator_audit_byzantine_boundary.csv",
            byzantine_boundary_sensitivity(
                threshold_runs,
                boundary_settings,
                aggregator_count=args.aggregator_count,
            ),
        )
    dropout_settings = [
        (5, 3, 0, 0),
        (5, 3, 0, 1),
        (5, 3, 0, 2),
        (5, 3, 0, 3),
        (7, 5, 0, 0),
        (7, 5, 0, 1),
        (7, 5, 0, 2),
        (7, 5, 0, 3),
    ]
    if args.section in {"all", "liveness"}:
        write_csv(
            out_dir / "validator_audit_liveness_dropout.csv",
            liveness_dropout_sensitivity(
                threshold_runs,
                dropout_settings,
                aggregator_count=args.aggregator_count,
            ),
        )
    accountability_settings = [
        (5, 3, 0, "honest_committee"),
        (5, 3, 2, "within_assumption"),
        (5, 3, 3, "assumption_violated"),
        (7, 5, 4, "within_assumption"),
        (7, 5, 5, "assumption_violated"),
    ]
    if args.section in {"all", "accountability"}:
        write_csv(
            out_dir / "validator_audit_accountability.csv",
            validator_accountability_sensitivity(
                threshold_runs,
                accountability_settings,
                aggregator_count=args.aggregator_count,
            ),
        )
    scalability_client_counts = [10, 20, 50, 100, 200]
    scalability_committees = [(3, 2), (5, 3), (7, 4), (9, 6), (11, 7)]
    if args.section in {"all", "scalability"}:
        write_csv(
            out_dir / "validator_audit_scalability.csv",
            validator_scalability_sweep(
                threshold_runs,
                scalability_client_counts,
                scalability_committees,
                aggregator_count=args.aggregator_count,
                max_runs=args.scalability_max_runs,
                max_blocks_per_run=args.scalability_max_blocks_per_run,
            ),
        )
    if args.section in {"all", "network_latency"}:
        scalability_path = out_dir / "validator_audit_scalability.csv"
        scalability_rows = read_csv_rows(scalability_path)
        if not scalability_rows:
            scalability_rows = [
                {key: str(value) for key, value in row.items()}
                for row in validator_scalability_sweep(
                    threshold_runs,
                    scalability_client_counts,
                    scalability_committees,
                    aggregator_count=args.aggregator_count,
                    max_runs=args.scalability_max_runs,
                    max_blocks_per_run=args.scalability_max_blocks_per_run,
                )
            ]
            write_csv(scalability_path, scalability_rows)
        latency_rows = network_latency_sensitivity(
            scalability_rows,
            bandwidth_mbps_values=[10.0, 50.0, 100.0],
            rtt_ms_values=[10.0, 50.0, 100.0],
        )
        write_csv(out_dir / "validator_audit_network_latency.csv", latency_rows)
        write_csv(out_dir / "validator_audit_network_latency_summary.csv", summarize_network_latency(latency_rows))
    if args.section in {"all", "network_events"}:
        scalability_path = out_dir / "validator_audit_scalability.csv"
        scalability_rows = read_csv_rows(scalability_path)
        if not scalability_rows:
            scalability_rows = [
                {key: str(value) for key, value in row.items()}
                for row in validator_scalability_sweep(
                    threshold_runs,
                    scalability_client_counts,
                    scalability_committees,
                    aggregator_count=args.aggregator_count,
                    max_runs=args.scalability_max_runs,
                    max_blocks_per_run=args.scalability_max_blocks_per_run,
                )
            ]
            write_csv(scalability_path, scalability_rows)
        event_rows = event_driven_finality_simulation(
            scalability_rows,
            bandwidth_mbps_values=[10.0, 100.0],
            rtt_ms_values=[10.0, 50.0, 100.0],
            dropout_rates=[0.0, 0.1, 0.2, 0.4],
        )
        write_csv(out_dir / "validator_audit_network_events.csv", event_rows)
        write_csv(out_dir / "validator_audit_network_events_summary.csv", summarize_event_driven_finality(event_rows))

    print(f"Evaluated validator-backed audit on {len(run_dirs)} runs")
    print(f"Section: {args.section}")
    print(f"Representative runs for threshold/boundary/liveness/accountability: {len(threshold_runs)}")
    print(f"Wrote tables to {out_dir}")


if __name__ == "__main__":
    main()
