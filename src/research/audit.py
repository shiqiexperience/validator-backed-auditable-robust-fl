"""Hash-chain audit logging for FL aggregation decisions."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, Mapping


def canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_payload(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


class AuditChainLogger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.previous_hash = "0" * 64
        if self.path.exists():
            self.previous_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        last = ""
        with open(self.path, "r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last = line
        if not last:
            return "0" * 64
        try:
            return json.loads(last)["hash"]
        except Exception:
            return "0" * 64

    def append(self, round_id: int, payload: Mapping[str, Any]) -> Dict[str, Any]:
        block = {
            "round": round_id,
            "timestamp": time.time(),
            "previous_hash": self.previous_hash,
            "payload": payload,
        }
        block["hash"] = hash_payload(block)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(block, ensure_ascii=False) + "\n")
        self.previous_hash = block["hash"]
        return block


def verify_chain(path: str | Path) -> bool:
    previous = "0" * 64
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            block = json.loads(line)
            found_hash = block.pop("hash")
            if block.get("previous_hash") != previous:
                return False
            if hash_payload(block) != found_hash:
                return False
            previous = found_hash
    return True

