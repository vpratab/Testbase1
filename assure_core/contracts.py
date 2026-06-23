"""Contracts that force each topic to have distinct mission semantics."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class ActionMode(str, Enum):
    ADVISORY = "advisory"
    AUTHORIZE = "authorize"
    ESCALATE = "escalate"
    PRIORITIZE = "prioritize"
    BROKER = "broker"
    MIGRATE = "migrate"


class FailurePosture(str, Enum):
    FAIL_CLOSED = "fail_closed"
    FLAG_AND_CONTINUE = "flag_and_continue"
    ADVISORY_ONLY = "advisory_only"
    PRESERVE_CUSTODY = "preserve_custody"
    QUARANTINE_TRANSACTION = "quarantine_transaction"


@dataclass(frozen=True)
class EvidenceSemantics:
    proves: tuple[str, ...]
    excludes: tuple[str, ...]
    retention: str
    verifier: str


@dataclass(frozen=True)
class TopicDesign:
    topic: str
    product_family: str
    mission_question: str
    action_mode: ActionMode
    failure_posture: FailurePosture
    input_contract: tuple[str, ...]
    maintained_state: tuple[str, ...]
    decision_contract: tuple[str, ...]
    evidence: EvidenceSemantics
    primary_metrics: tuple[str, ...]
    philosophy_mapping: tuple[str, ...]
    known_boundary: tuple[str, ...]

    @property
    def fingerprint(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True, default=str).encode()
        return hashlib.sha256(payload).hexdigest()

    def validate(self) -> None:
        required = {
            "input_contract": self.input_contract,
            "maintained_state": self.maintained_state,
            "decision_contract": self.decision_contract,
            "primary_metrics": self.primary_metrics,
            "philosophy_mapping": self.philosophy_mapping,
            "known_boundary": self.known_boundary,
        }
        for name, values in required.items():
            if not values:
                raise ValueError(f"{self.topic}: {name} cannot be empty")
        if set(self.evidence.proves) & set(self.evidence.excludes):
            raise ValueError(f"{self.topic}: evidence proves/excludes overlap")


@dataclass(frozen=True)
class AssuranceDecision:
    topic: str
    action: str
    confidence: float
    reasons: tuple[str, ...]
    state_digest: str
    evidence_payload: dict[str, Any]

    def validate(self, design: TopicDesign) -> None:
        if self.topic != design.topic:
            raise ValueError("decision topic does not match design")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be within [0, 1]")
        if not self.reasons:
            raise ValueError("decision must be explainable")
        missing = [
            field
            for field in design.decision_contract
            if field not in self.evidence_payload
        ]
        if missing:
            raise ValueError(
                f"{self.topic}: decision evidence missing required fields {missing}"
            )


def state_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, default=str).encode()
    return hashlib.sha384(payload).hexdigest()
