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


def build_proposed_block(
    source_block: Mapping[str, Any],
    previous_hash: str,
    client_secrets: Mapping[int, str],
    aggregator_id: int | None = None,
    aggregator_secret: str | None = None,
) -> dict[str, Any]:
    """Build an aggregator-proposed block from the existing audit payload."""

    payload = copy.deepcopy(source_block["payload"])
    commitments = [
        make_client_commitment(int(source_block["round"]), client, client_secrets[int(client["client_id"])])
        for client in payload.get("clients", [])
    ]
    proposed = {
        "round": int(source_block["round"]),
        "timestamp": float(source_block.get("timestamp", time.time())),
        "previous_hash": previous_hash,
        "payload": payload,
        "client_commitments": [commitment.to_record() for commitment in commitments],
    }
    proposed["payload_hash"] = hash_payload(payload)
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
    commitments = {
        int(commitment["client_id"]): commitment
        for commitment in proposed_block.get("client_commitments", [])
    }

    if set(clients) != set(decisions) or set(clients) != set(commitments):
        return False, "client_decision_commitment_set_mismatch"

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


def tamper_block(proposed_block: Mapping[str, Any], scenario: str) -> dict[str, Any]:
    """Return a tampered proposed block without recomputing proposal hashes."""

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
    elif scenario == "unauthorized_aggregator":
        block["aggregator_id"] = int(block.get("aggregator_id", 0)) + 1
    elif scenario == "aggregator_signature_tamper":
        block["aggregator_signature"] = sha256_hex("bad-aggregator-signature")
    elif scenario == "aggregator_equivocation":
        payload["model_hash"] = sha256_hex("equivocated-model")
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
