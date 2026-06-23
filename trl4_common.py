"""Shared measurement, evidence, and scoring utilities for the TRL 3/4 campaign."""

from __future__ import annotations

import hashlib
import json
import math
import platform
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519


def percentile(values: Iterable[float], q: float) -> float:
    array = np.asarray(list(values), dtype=float)
    if array.size == 0:
        return math.nan
    return float(np.quantile(array, q))


def binary_metrics(y_true: Iterable[bool], y_pred: Iterable[bool]) -> dict[str, float]:
    truth = np.asarray(list(y_true), dtype=bool)
    predicted = np.asarray(list(y_pred), dtype=bool)
    tp = int(np.sum(truth & predicted))
    fp = int(np.sum(~truth & predicted))
    fn = int(np.sum(truth & ~predicted))
    tn = int(np.sum(~truth & ~predicted))
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    return {
        "precision": precision,
        "recall": recall,
        "f1": 2.0 * precision * recall / max(precision + recall, 1.0e-12),
        "false_positive_rate": fp / max(fp + tn, 1),
        "false_negative_rate": fn / max(fn + tp, 1),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
    }


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


class EvidenceChain:
    """Signed append-only evidence chain with independent verification."""

    def __init__(self, seed: bytes | None = None) -> None:
        if seed is None:
            self._signer = ed25519.Ed25519PrivateKey.generate()
        else:
            self._signer = ed25519.Ed25519PrivateKey.from_private_bytes(
                hashlib.sha256(seed).digest()
            )
        self._previous = bytes(32)
        self._records: list[dict[str, Any]] = []

    @property
    def public_key(self) -> ed25519.Ed25519PublicKey:
        return self._signer.public_key()

    @property
    def records(self) -> list[dict[str, Any]]:
        return list(self._records)

    @property
    def head(self) -> str:
        return self._previous.hex()

    def append(self, topic: str, event: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "sequence": len(self._records),
            "topic": topic,
            "event": event,
            "previous_hash": self._previous.hex(),
        }
        event_hash = hashlib.sha256(self._previous + canonical_json(payload)).digest()
        record = {
            **payload,
            "event_hash": event_hash.hex(),
            "signature": self._signer.sign(event_hash).hex(),
        }
        self._records.append(record)
        self._previous = event_hash
        return record

    @staticmethod
    def verify(
        records: Iterable[dict[str, Any]],
        public_key: ed25519.Ed25519PublicKey,
    ) -> bool:
        previous = bytes(32)
        expected_sequence = 0
        for record in records:
            if record.get("sequence") != expected_sequence:
                return False
            if record.get("previous_hash") != previous.hex():
                return False
            payload = {
                "sequence": record["sequence"],
                "topic": record["topic"],
                "event": record["event"],
                "previous_hash": record["previous_hash"],
            }
            event_hash = hashlib.sha256(previous + canonical_json(payload)).digest()
            if event_hash.hex() != record.get("event_hash"):
                return False
            try:
                public_key.verify(
                    bytes.fromhex(record["signature"]),
                    event_hash,
                )
            except (InvalidSignature, ValueError):
                return False
            previous = event_hash
            expected_sequence += 1
        return True


def tamper_test(
    records: list[dict[str, Any]],
    public_key: ed25519.Ed25519PublicKey,
) -> bool:
    if not records:
        return False
    tampered = json.loads(json.dumps(records))
    index = len(tampered) // 2
    tampered[index]["event"]["tampered"] = True
    return not EvidenceChain.verify(tampered, public_key)


@dataclass(frozen=True)
class RequirementGate:
    name: str
    weight: float
    achieved: float
    evidence: str

    @property
    def points(self) -> float:
        return self.weight * min(max(self.achieved, 0.0), 1.0)


def score_gates(gates: Iterable[RequirementGate]) -> dict[str, Any]:
    gate_list = list(gates)
    maximum = sum(gate.weight for gate in gate_list)
    points = sum(gate.points for gate in gate_list)
    score = 100.0 * points / max(maximum, 1.0e-12)
    return {
        "score": round(score, 1),
        "points": round(points, 3),
        "maximum_points": round(maximum, 3),
        "gates": [
            {
                **asdict(gate),
                "points": round(gate.points, 3),
            }
            for gate in gate_list
        ],
    }


def replace_gate(
    score: dict[str, Any],
    name: str,
    achieved: float,
    evidence: str,
) -> None:
    """Update one traceability gate without importing a campaign runner."""
    target = next(gate for gate in score["gates"] if gate["name"] == name)
    target["achieved"] = float(max(0.0, min(achieved, 1.0)))
    target["evidence"] = evidence
    target["points"] = round(target["weight"] * target["achieved"], 3)


def recompute_score(score: dict[str, Any]) -> None:
    """Recompute a requirement-match score after one or more gate updates."""
    score["points"] = round(sum(gate["points"] for gate in score["gates"]), 3)
    score["score"] = round(
        100.0 * score["points"] / max(score["maximum_points"], 1.0e-12),
        1,
    )


def runtime_metadata() -> dict[str, Any]:
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
    }


def to_builtin(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): to_builtin(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_builtin(item) for item in value]
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, Path):
        return str(value)
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(to_builtin(value), indent=2, sort_keys=True, default=str) + "\n"
    )
