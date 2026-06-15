"""Validator-backed audit protocol simulation.

This module separates aggregation from audit finalization. The aggregation
server proposes a block, while independent validators verify client
commitments, decision consistency, hash linkage, and threshold finality.
The decentralized extension models a permissioned ledger setting in which the
round aggregator is selected by a public rule and cannot finalize blocks alone.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import math
import time
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


GENESIS_HASH = "0" * 64


def canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str | bytes) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def hash_payload(payload: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_json(payload))


def _sign(secret: str, message: str) -> str:
    return hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def _verify(secret: str, message: str, signature: str) -> bool:
    expected = _sign(secret, message)
    return hmac.compare_digest(expected, signature)


def select_aggregator(round_id: int, aggregator_ids: Sequence[int]) -> int:
    """Select a round aggregator by deterministic round-robin rotation."""

    if not aggregator_ids:
        raise ValueError("aggregator_ids cannot be empty")
    ordered = sorted(int(aggregator_id) for aggregator_id in aggregator_ids)
    return ordered[(int(round_id) - 1) % len(ordered)]


def make_aggregator_secrets(aggregator_ids: Sequence[int]) -> dict[int, str]:
    return {int(aggregator_id): f"aggregator-secret-{int(aggregator_id)}" for aggregator_id in aggregator_ids}


def _aggregator_message(proposed_block: Mapping[str, Any]) -> str:
    return canonical_json(
        {
            "round": int(proposed_block["round"]),
            "aggregator_id": int(proposed_block["aggregator_id"]),
            "previous_hash": str(proposed_block["previous_hash"]),
            "payload_hash": str(proposed_block["payload_hash"]),
            "evidence_hash": str(proposed_block.get("evidence_hash", "")),
        }
    )


@dataclass(frozen=True)
class ClientCommitment:
    round_id: int
    client_id: int
    update_hash: str
    num_samples: int
    metadata_hash: str
    signature: str

    def to_record(self) -> dict[str, Any]:
        return {
            "round_id": self.round_id,
            "client_id": self.client_id,
            "update_hash": self.update_hash,
            "num_samples": self.num_samples,
            "metadata_hash": self.metadata_hash,
            "signature": self.signature,
        }


@dataclass(frozen=True)
class VerificationResult:
    validator_id: int
    accepted: bool
    reason: str
    signature: str | None = None


def make_client_commitment(
    round_id: int,
    client_record: Mapping[str, Any],
    client_secret: str,
) -> ClientCommitment:
    """Create a signed commitment from an existing client-round record."""

    client_id = int(client_record["client_id"])
    metadata = {
        "round": int(client_record["round"]),
        "client_id": client_id,
        "num_samples": int(client_record.get("num_samples", 0)),
        "update_norm": float(client_record.get("update_norm", 0.0)),
        "selected": int(client_record.get("selected", 1)),
    }
    metadata_hash = hash_payload(metadata)
    update_hash = sha256_hex(
        f"{round_id}:{client_id}:{float(client_record.get('update_norm', 0.0)):.12f}:{metadata_hash}"
    )
    message = canonical_json(
        {
            "round_id": round_id,
            "client_id": client_id,
            "update_hash": update_hash,
            "num_samples": int(client_record.get("num_samples", 0)),
            "metadata_hash": metadata_hash,
        }
    )
    return ClientCommitment(
        round_id=round_id,
        client_id=client_id,
        update_hash=update_hash,
        num_samples=int(client_record.get("num_samples", 0)),
        metadata_hash=metadata_hash,
        signature=_sign(client_secret, message),
    )


def verify_client_commitment(commitment: Mapping[str, Any], client_secret: str) -> bool:
    message = canonical_json(
        {
            "round_id": int(commitment["round_id"]),
            "client_id": int(commitment["client_id"]),
            "update_hash": str(commitment["update_hash"]),
            "num_samples": int(commitment["num_samples"]),
            "metadata_hash": str(commitment["metadata_hash"]),
        }
    )
    return _verify(client_secret, message, str(commitment["signature"]))


def _metadata_hash_from_client_record(round_id: int, client_record: Mapping[str, Any]) -> str:
    metadata = {
        "round": int(client_record.get("round", round_id)),
        "client_id": int(client_record["client_id"]),
        "num_samples": int(client_record.get("num_samples", 0)),
        "update_norm": float(client_record.get("update_norm", 0.0)),
        "selected": int(client_record.get("selected", 1)),
    }
    return hash_payload(metadata)


def _update_hash_from_client_record(round_id: int, client_record: Mapping[str, Any], metadata_hash: str) -> str:
    return sha256_hex(
        f"{round_id}:{int(client_record['client_id'])}:"
        f"{float(client_record.get('update_norm', 0.0)):.12f}:{metadata_hash}"
    )


def _build_decision_evidence(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    clients = {int(client["client_id"]): client for client in payload.get("clients", [])}
    evidence = []
    for decision in payload.get("decisions", []):
        client_id = int(float(decision["client_id"]))
        client = clients.get(client_id, {})
        evidence.append(
            {
                "client_id": client_id,
                "round": int(client.get("round", payload.get("metrics", {}).get("round", 0))),
                "num_samples": int(client.get("num_samples", 0)),
                "update_norm": float(client.get("update_norm", decision.get("norm", 0.0))),
                "selected": int(client.get("selected", 1)),
                "norm": float(decision.get("norm", client.get("update_norm", 0.0))),
                "direction": float(decision.get("direction", 0.0)),
                "norm_score": float(decision.get("norm_score", 0.0)),
                "history_score": float(decision.get("history_score", 0.0)),
                "reputation_before": float(decision.get("reputation_before", 1.0)),
                "use_direction_score": float(decision.get("use_direction_score", 1.0)),
                "use_history_score": float(decision.get("use_history_score", 1.0)),
                "use_hard_rejection": float(decision.get("use_hard_rejection", 1.0)),
            }
        )
    return evidence


def build_round_evidence(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Build the off-chain evidence package used by validators.

    The benchmark stores a compact deterministic representation rather than full
    model-update tensors. It contains the scalar evidence required to recompute
    the proposed decision fields.
    """

    evidence_rows = _build_decision_evidence(payload)
    first = evidence_rows[0] if evidence_rows else {}
    return {
        "schema": "validator-round-evidence-v1",
        "decision_evidence": evidence_rows,
        "aggregation_params": {
            "norm_coefficient": float(first.get("norm_coefficient", 0.45)),
            "direction_coefficient": float(first.get("direction_coefficient", 0.35)),
            "history_coefficient": float(first.get("history_coefficient", 0.20)),
            "reputation_decay": 0.85,
            "reputation_update_rate": 0.15,
            "reputation_min": 0.05,
            "reputation_max": 1.5,
            "anomaly_reject_threshold": 4.0,
            "threshold_scale": 2.5,
            "direction_reject_threshold": -0.4,
            "min_weight": 0.0,
            "weight_temperature": 1.2,
            "fallback_accept_fraction": 0.5,
        },
    }


def build_proposed_block(
    source_block: Mapping[str, Any],
    previous_hash: str,
    client_secrets: Mapping[int, str],
    aggregator_id: int | None = None,
    aggregator_secret: str | None = None,
) -> dict[str, Any]:
    """Build an aggregator-proposed block from the existing audit payload."""

    payload = copy.deepcopy(source_block["payload"])
    evidence = build_round_evidence(payload)
    commitments = [
        make_client_commitment(int(source_block["round"]), client, client_secrets[int(client["client_id"])])
        for client in payload.get("clients", [])
    ]
    proposed = {
        "round": int(source_block["round"]),
        "timestamp": float(source_block.get("timestamp", time.time())),
        "previous_hash": previous_hash,
        "payload": payload,
        "evidence": evidence,
        "client_commitments": [commitment.to_record() for commitment in commitments],
    }
    proposed["payload_hash"] = hash_payload(payload)
    proposed["evidence_hash"] = hash_payload(evidence)
    if aggregator_id is not None:
        if aggregator_secret is None:
            raise ValueError("aggregator_secret is required when aggregator_id is set")
        proposed["aggregator_id"] = int(aggregator_id)
        proposed["aggregator_signature"] = _sign(aggregator_secret, _aggregator_message(proposed))
    proposed["proposal_hash"] = hash_payload(proposed)
    return proposed


def _decision_map(proposed_block: Mapping[str, Any]) -> dict[int, Mapping[str, Any]]:
    return {
        int(float(decision["client_id"])): decision
        for decision in proposed_block.get("payload", {}).get("decisions", [])
    }


def _client_map(proposed_block: Mapping[str, Any]) -> dict[int, Mapping[str, Any]]:
    return {
        int(client["client_id"]): client
        for client in proposed_block.get("payload", {}).get("clients", [])
    }


def _evidence_map(proposed_block: Mapping[str, Any]) -> dict[int, Mapping[str, Any]]:
    return {
        int(evidence["client_id"]): evidence
        for evidence in proposed_block.get("evidence", {}).get("decision_evidence", [])
    }


def _recompute_decisions_from_evidence(
    proposed_block: Mapping[str, Any],
) -> tuple[dict[int, dict[str, float]], str]:
    evidence_package = proposed_block.get("evidence")
    if not isinstance(evidence_package, Mapping):
        return {}, "missing_evidence_package"
    params = evidence_package.get("aggregation_params", {})
    if not isinstance(params, Mapping):
        return {}, "missing_aggregation_params"

    norm_coeff = float(params.get("norm_coefficient", 0.45))
    direction_coeff_default = float(params.get("direction_coefficient", 0.35))
    history_coeff_default = float(params.get("history_coefficient", 0.20))
    rep_decay = float(params.get("reputation_decay", 0.85))
    rep_update = float(params.get("reputation_update_rate", 0.15))
    rep_min = float(params.get("reputation_min", 0.05))
    rep_max = float(params.get("reputation_max", 1.5))
    anomaly_threshold = float(params.get("anomaly_reject_threshold", 4.0))
    threshold_scale = float(params.get("threshold_scale", 2.5))
    direction_reject_threshold = float(params.get("direction_reject_threshold", -0.4))
    min_weight = float(params.get("min_weight", 0.0))
    temperature = float(params.get("weight_temperature", 1.2))
    fallback_fraction = float(params.get("fallback_accept_fraction", 0.5))

    raw: dict[int, dict[str, float]] = {}
    raw_weights: dict[int, float] = {}
    evidence_rows = evidence_package.get("decision_evidence", [])
    if not isinstance(evidence_rows, Sequence):
        return {}, "invalid_decision_evidence"

    for row in evidence_rows:
        client_id = int(row["client_id"])
        use_direction = float(row.get("use_direction_score", 1.0)) > 0.5
        use_history = float(row.get("use_history_score", 1.0)) > 0.5
        use_hard = float(row.get("use_hard_rejection", 1.0)) > 0.5
        norm_score = float(row.get("norm_score", 0.0))
        direction = float(row.get("direction", 0.0))
        direction_score = max(0.0, 1.0 - direction) if use_direction else 0.0
        history_score = float(row.get("history_score", 0.0)) if use_history else 0.0
        direction_coeff = direction_coeff_default if use_direction else 0.0
        history_coeff = history_coeff_default if use_history else 0.0
        total_coeff = max(norm_coeff + direction_coeff + history_coeff, 1e-12)
        anomaly = (
            norm_coeff * norm_score
            + direction_coeff * direction_score
            + history_coeff * history_score
        ) / total_coeff
        rep_before = float(row.get("reputation_before", 1.0))
        rep_after = max(rep_min, min(rep_max, rep_decay * rep_before + rep_update * math.exp(-anomaly)))
        hard_reject = False
        if use_hard:
            hard_reject = (
                anomaly > anomaly_threshold
                or (norm_score > threshold_scale and direction < 0.0)
                or (use_direction and direction < direction_reject_threshold)
            )
        weight = 0.0 if hard_reject else max(min_weight, rep_after * math.exp(-temperature * anomaly))
        raw_weights[client_id] = weight
        raw[client_id] = {
            "norm_score": norm_score,
            "history_score": history_score,
            "anomaly_score": anomaly,
            "reputation_before": rep_before,
            "reputation_after": rep_after,
            "aggregation_weight": weight,
            "rejected": 1.0 if hard_reject else 0.0,
        }

    if raw and sum(raw_weights.values()) <= 0.0:
        accept_count = max(1, int(math.ceil(len(raw) * fallback_fraction)))
        accepted = {
            client_id
            for client_id, _ in sorted(raw.items(), key=lambda item: item[1]["anomaly_score"])[:accept_count]
        }
        for client_id, values in raw.items():
            if client_id in accepted:
                fallback_weight = max(1e-6, values["reputation_after"] * math.exp(-temperature * values["anomaly_score"]))
                values["aggregation_weight"] = fallback_weight
                values["rejected"] = 0.0
                values["fallback_selected"] = 1.0
            else:
                values["aggregation_weight"] = 0.0
                values["fallback_selected"] = 0.0

    return raw, "accepted"


def verify_proposed_block(
    proposed_block: Mapping[str, Any],
    previous_hash: str,
    client_secrets: Mapping[int, str],
    aggregator_ids: Sequence[int] | None = None,
    aggregator_secrets: Mapping[int, str] | None = None,
    tolerance: float = 1e-9,
) -> tuple[bool, str]:
    """Verify an aggregator-proposed block using public rules and commitments."""

    if proposed_block.get("previous_hash") != previous_hash:
        return False, "previous_hash_mismatch"

    payload = proposed_block.get("payload", {})
    if hash_payload(payload) != proposed_block.get("payload_hash"):
        return False, "payload_hash_mismatch"

    evidence = proposed_block.get("evidence")
    if not isinstance(evidence, Mapping):
        return False, "missing_evidence_package"
    if hash_payload(evidence) != proposed_block.get("evidence_hash"):
        return False, "evidence_hash_mismatch"

    proposal_copy = copy.deepcopy(dict(proposed_block))
    found_proposal_hash = proposal_copy.pop("proposal_hash", "")
    if hash_payload(proposal_copy) != found_proposal_hash:
        return False, "proposal_hash_mismatch"

    if aggregator_ids is not None:
        if "aggregator_id" not in proposed_block or "aggregator_signature" not in proposed_block:
            return False, "missing_aggregator_authorization"
        aggregator_id = int(proposed_block["aggregator_id"])
        expected_aggregator = select_aggregator(int(proposed_block["round"]), aggregator_ids)
        if aggregator_id != expected_aggregator:
            return False, "unauthorized_aggregator"
        if aggregator_secrets is None or aggregator_id not in aggregator_secrets:
            return False, "unknown_aggregator"
        if not _verify(
            aggregator_secrets[aggregator_id],
            _aggregator_message(proposed_block),
            str(proposed_block["aggregator_signature"]),
        ):
            return False, "aggregator_signature_invalid"

    clients = _client_map(proposed_block)
    decisions = _decision_map(proposed_block)
    evidence_rows = _evidence_map(proposed_block)
    commitments = {
        int(commitment["client_id"]): commitment
        for commitment in proposed_block.get("client_commitments", [])
    }

    if set(clients) != set(decisions) or set(clients) != set(commitments) or set(clients) != set(evidence_rows):
        return False, "client_decision_commitment_evidence_set_mismatch"

    for client_id, commitment in commitments.items():
        secret = client_secrets.get(client_id)
        if secret is None:
            return False, "unknown_client_commitment"
        if not verify_client_commitment(commitment, secret):
            return False, "client_signature_invalid"
        if int(commitment["round_id"]) != int(proposed_block["round"]):
            return False, "client_round_mismatch"
        if int(commitment["num_samples"]) != int(clients[client_id].get("num_samples", 0)):
            return False, "client_sample_count_mismatch"
        expected_metadata_hash = _metadata_hash_from_client_record(int(proposed_block["round"]), clients[client_id])
        expected_update_hash = _update_hash_from_client_record(
            int(proposed_block["round"]),
            clients[client_id],
            expected_metadata_hash,
        )
        if str(commitment["metadata_hash"]) != expected_metadata_hash:
            return False, "client_metadata_hash_mismatch"
        if str(commitment["update_hash"]) != expected_update_hash:
            return False, "client_update_hash_mismatch"

        evidence_row = evidence_rows[client_id]
        if int(evidence_row.get("num_samples", -1)) != int(clients[client_id].get("num_samples", 0)):
            return False, "evidence_sample_count_mismatch"
        if abs(float(evidence_row.get("update_norm", 0.0)) - float(clients[client_id].get("update_norm", 0.0))) > tolerance:
            return False, "evidence_update_norm_mismatch"

    recomputed, reason = _recompute_decisions_from_evidence(proposed_block)
    if reason != "accepted":
        return False, reason

    for client_id, decision in decisions.items():
        client_weight = float(clients[client_id].get("aggregation_weight", 0.0))
        decision_weight = float(decision.get("aggregation_weight", 0.0))
        if abs(client_weight - decision_weight) > tolerance:
            return False, "aggregation_weight_mismatch"
        rejected = float(decision.get("rejected", 0.0)) > 0.5
        if rejected and decision_weight > tolerance:
            return False, "rejected_client_has_positive_weight"
        for field in [
            "norm",
            "direction",
            "norm_score",
            "history_score",
            "anomaly_score",
            "reputation_before",
            "reputation_after",
        ]:
            if field not in decision:
                return False, f"missing_decision_field:{field}"
        expected = recomputed.get(client_id)
        if expected is None:
            return False, "missing_recomputed_decision"
        for field in [
            "norm_score",
            "history_score",
            "anomaly_score",
            "reputation_before",
            "reputation_after",
            "aggregation_weight",
            "rejected",
        ]:
            if abs(float(decision.get(field, 0.0)) - float(expected.get(field, 0.0))) > tolerance:
                return False, f"decision_recompute_mismatch:{field}"

    return True, "accepted"


@dataclass
class Validator:
    validator_id: int
    secret: str
    byzantine: bool = False
    byzantine_accept_invalid: bool = False
    offline: bool = False

    def verify(
        self,
        proposed_block: Mapping[str, Any],
        previous_hash: str,
        client_secrets: Mapping[int, str],
        aggregator_ids: Sequence[int] | None = None,
        aggregator_secrets: Mapping[int, str] | None = None,
    ) -> VerificationResult:
        if self.offline:
            return VerificationResult(self.validator_id, False, "validator_offline", None)

        accepted, reason = verify_proposed_block(
            proposed_block,
            previous_hash,
            client_secrets,
            aggregator_ids=aggregator_ids,
            aggregator_secrets=aggregator_secrets,
        )
        if self.byzantine and self.byzantine_accept_invalid:
            accepted = True
            reason = "byzantine_accept"
        elif self.byzantine and not self.byzantine_accept_invalid:
            accepted = False
            reason = "byzantine_reject"

        signature = None
        if accepted:
            signature = _sign(self.secret, str(proposed_block["proposal_hash"]))
        return VerificationResult(self.validator_id, accepted, reason, signature)


@dataclass
class FinalizedBlock:
    round_id: int
    previous_hash: str
    proposal_hash: str
    payload_hash: str
    validator_signatures: list[dict[str, Any]]
    rejected_votes: list[dict[str, Any]]
    finalized: bool
    block_hash: str

    def to_record(self) -> dict[str, Any]:
        return {
            "round_id": self.round_id,
            "previous_hash": self.previous_hash,
            "proposal_hash": self.proposal_hash,
            "payload_hash": self.payload_hash,
            "validator_signatures": self.validator_signatures,
            "rejected_votes": self.rejected_votes,
            "finalized": self.finalized,
            "block_hash": self.block_hash,
        }


class ValidatorCommittee:
    def __init__(self, validators: Sequence[Validator], threshold: int):
        if threshold < 1:
            raise ValueError("threshold must be positive")
        if threshold > len(validators):
            raise ValueError("threshold cannot exceed validator count")
        self.validators = list(validators)
        self.threshold = int(threshold)

    def finalize(
        self,
        proposed_block: Mapping[str, Any],
        previous_hash: str,
        client_secrets: Mapping[int, str],
        aggregator_ids: Sequence[int] | None = None,
        aggregator_secrets: Mapping[int, str] | None = None,
    ) -> FinalizedBlock:
        results = [
            validator.verify(
                proposed_block,
                previous_hash,
                client_secrets,
                aggregator_ids=aggregator_ids,
                aggregator_secrets=aggregator_secrets,
            )
            for validator in self.validators
        ]
        accepted = [result for result in results if result.accepted and result.signature]
        rejected = [result for result in results if not result.accepted]
        finalized = len(accepted) >= self.threshold
        record_without_hash = {
            "round_id": int(proposed_block["round"]),
            "previous_hash": previous_hash,
            "proposal_hash": proposed_block["proposal_hash"],
            "payload_hash": proposed_block["payload_hash"],
            "validator_signatures": [
                {
                    "validator_id": result.validator_id,
                    "signature": result.signature,
                    "reason": result.reason,
                }
                for result in accepted
            ],
            "rejected_votes": [
                {
                    "validator_id": result.validator_id,
                    "reason": result.reason,
                }
                for result in rejected
            ],
            "finalized": finalized,
        }
        return FinalizedBlock(
            round_id=record_without_hash["round_id"],
            previous_hash=previous_hash,
            proposal_hash=record_without_hash["proposal_hash"],
            payload_hash=record_without_hash["payload_hash"],
            validator_signatures=record_without_hash["validator_signatures"],
            rejected_votes=record_without_hash["rejected_votes"],
            finalized=finalized,
            block_hash=hash_payload(record_without_hash),
        )


def make_validators(
    count: int,
    byzantine_count: int = 0,
    accept_invalid: bool = True,
    offline_count: int = 0,
) -> list[Validator]:
    validators = []
    for idx in range(count):
        validators.append(
            Validator(
                validator_id=idx,
                secret=f"validator-secret-{idx}",
                byzantine=idx < byzantine_count,
                byzantine_accept_invalid=accept_invalid,
                offline=(count - offline_count) <= idx,
            )
        )
    return validators


def make_client_secrets(client_ids: Sequence[int]) -> dict[int, str]:
    return {int(client_id): f"client-secret-{int(client_id)}" for client_id in client_ids}


def refresh_proposal_integrity(block: dict[str, Any], aggregator_secret: str | None = None) -> dict[str, Any]:
    """Recompute hashes and optional aggregator signature after proposal edits."""

    block["payload_hash"] = hash_payload(block.get("payload", {}))
    if "evidence" in block:
        block["evidence_hash"] = hash_payload(block.get("evidence", {}))
    if aggregator_secret is not None and "aggregator_id" in block:
        block["aggregator_signature"] = _sign(aggregator_secret, _aggregator_message(block))
    block_without_hash = copy.deepcopy(block)
    block_without_hash.pop("proposal_hash", None)
    block["proposal_hash"] = hash_payload(block_without_hash)
    return block


def tamper_block(
    proposed_block: Mapping[str, Any],
    scenario: str,
    aggregator_secret: str | None = None,
) -> dict[str, Any]:
    """Return a tampered proposed block.

    Most scenarios leave hashes stale, modeling simple tampering. The
    self-consistent scenarios recompute hashes and the aggregator signature so
    validators must rely on evidence recomputation rather than hash mismatch.
    """

    block = copy.deepcopy(dict(proposed_block))
    payload = block.setdefault("payload", {})
    if scenario == "score_tamper":
        payload["decisions"][0]["anomaly_score"] = float(payload["decisions"][0]["anomaly_score"]) + 1.0
    elif scenario == "weight_tamper":
        payload["decisions"][0]["aggregation_weight"] = float(payload["decisions"][0]["aggregation_weight"]) + 0.1
    elif scenario == "client_weight_tamper":
        payload["clients"][0]["aggregation_weight"] = float(payload["clients"][0]["aggregation_weight"]) + 0.1
    elif scenario == "model_hash_tamper":
        payload["model_hash"] = sha256_hex("tampered-model")
    elif scenario == "previous_hash_tamper":
        block["previous_hash"] = sha256_hex("tampered-previous")
    elif scenario == "omit_client":
        payload["clients"] = payload["clients"][1:]
    elif scenario == "fake_client":
        fake = copy.deepcopy(payload["clients"][0])
        fake["client_id"] = 999
        payload["clients"].append(fake)
    elif scenario == "client_signature_tamper":
        block["client_commitments"][0]["signature"] = sha256_hex("bad-signature")
    elif scenario == "payload_hash_tamper":
        block["payload_hash"] = sha256_hex("bad-payload-hash")
    elif scenario == "evidence_hash_tamper":
        block["evidence_hash"] = sha256_hex("bad-evidence-hash")
    elif scenario == "missing_evidence":
        block.pop("evidence", None)
    elif scenario == "unauthorized_aggregator":
        block["aggregator_id"] = int(block.get("aggregator_id", 0)) + 1
    elif scenario == "aggregator_signature_tamper":
        block["aggregator_signature"] = sha256_hex("bad-aggregator-signature")
    elif scenario == "aggregator_equivocation":
        payload["model_hash"] = sha256_hex("equivocated-model")
    elif scenario == "self_consistent_score_tamper":
        payload["decisions"][0]["anomaly_score"] = float(payload["decisions"][0]["anomaly_score"]) + 1.0
        refresh_proposal_integrity(block, aggregator_secret)
    elif scenario == "self_consistent_weight_tamper":
        new_weight = float(payload["decisions"][0]["aggregation_weight"]) + 0.1
        payload["decisions"][0]["aggregation_weight"] = new_weight
        payload["clients"][0]["aggregation_weight"] = new_weight
        refresh_proposal_integrity(block, aggregator_secret)
    elif scenario == "evidence_score_tamper":
        block["evidence"]["decision_evidence"][0]["norm_score"] = (
            float(block["evidence"]["decision_evidence"][0]["norm_score"]) + 1.0
        )
        refresh_proposal_integrity(block, aggregator_secret)
    else:
        raise ValueError(f"unknown tampering scenario: {scenario}")
    return block


def detect_equivocation(finalized_blocks: Sequence[Mapping[str, Any]]) -> tuple[bool, str]:
    """Detect multiple finalized proposals by the same aggregator for one round."""

    seen: dict[tuple[int, int], str] = {}
    for block in finalized_blocks:
        aggregator_id = block.get("aggregator_id")
        if aggregator_id is None:
            continue
        key = (int(block["round"]), int(aggregator_id))
        proposal_hash = str(block["proposal_hash"])
        previous = seen.get(key)
        if previous is not None and previous != proposal_hash:
            return True, "aggregator_equivocation_detected"
        seen[key] = proposal_hash
    return False, "no_equivocation"
