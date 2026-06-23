"""PZDR-derived primitives: constrain, attest, minimize, and prove."""

from __future__ import annotations

import hashlib
import heapq
import time
from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass(frozen=True)
class TrustLease:
    """Bounded offline authority that expires rather than silently widening trust."""

    policy_version: str
    identity_version: str
    issued_at: float
    expires_at: float
    permitted_actions: frozenset[str]
    permitted_resources: frozenset[str]
    issuer_signature_valid: bool

    def authorize(self, now: float, action: str, resource: str) -> tuple[bool, str]:
        if not self.issuer_signature_valid:
            return False, "trust_lease_signature_invalid"
        if now > self.expires_at:
            return False, "trust_lease_expired"
        if action not in self.permitted_actions:
            return False, "action_outside_trust_lease"
        if resource not in self.permitted_resources:
            return False, "resource_outside_trust_lease"
        return True, "bounded_offline_authority_valid"


@dataclass(frozen=True)
class PurposeBoundIntent:
    """An action envelope whose authority is restricted to one stated purpose."""

    intent_id: str
    purpose: str
    subject: str
    object_id: str
    action: str
    valid_from: float
    valid_until: float
    maximum_uses: int = 1

    @property
    def commitment(self) -> str:
        material = (
            f"{self.intent_id}|{self.purpose}|{self.subject}|{self.object_id}|"
            f"{self.action}|{self.valid_from}|{self.valid_until}|{self.maximum_uses}"
        )
        return hashlib.sha384(material.encode()).hexdigest()

    def permits(
        self,
        *,
        now: float,
        subject: str,
        object_id: str,
        action: str,
        use_count: int,
    ) -> tuple[bool, str]:
        if not self.valid_from <= now <= self.valid_until:
            return False, "intent_outside_validity_window"
        if subject != self.subject:
            return False, "intent_subject_mismatch"
        if object_id != self.object_id:
            return False, "intent_object_mismatch"
        if action != self.action:
            return False, "intent_action_mismatch"
        if use_count >= self.maximum_uses:
            return False, "intent_use_limit_exceeded"
        return True, "purpose_bound_intent_valid"


@dataclass(frozen=True)
class ProcessingReceipt:
    operation_id: str
    input_commitment: str
    output_commitment: str
    policy_version: str
    code_identity: str
    started_at: float
    completed_at: float
    ephemeral_material_destroyed: bool
    result: str


@dataclass
class CryptoAssetNode:
    asset_id: str
    algorithm: str
    risk: float
    dependencies: set[str] = field(default_factory=set)
    migration_target: str = ""
    effort: float = 1.0


class MigrationWavePlanner:
    """Orders cryptographic migration without breaking dependency chains."""

    def __init__(self, assets: Iterable[CryptoAssetNode]) -> None:
        self.assets = {asset.asset_id: asset for asset in assets}

    def plan(self, lanes: int = 4) -> dict[str, Any]:
        dependents: dict[str, set[str]] = {asset_id: set() for asset_id in self.assets}
        remaining_dependencies: dict[str, set[str]] = {}
        for asset_id, asset in self.assets.items():
            known = {dependency for dependency in asset.dependencies if dependency in self.assets}
            remaining_dependencies[asset_id] = set(known)
            for dependency in known:
                dependents[dependency].add(asset_id)

        ready: list[tuple[float, str]] = [
            (-asset.risk, asset_id)
            for asset_id, asset in self.assets.items()
            if not remaining_dependencies[asset_id]
        ]
        heapq.heapify(ready)
        waves: list[list[str]] = []
        visited: set[str] = set()
        while ready:
            wave: list[str] = []
            while ready and len(wave) < lanes:
                _, asset_id = heapq.heappop(ready)
                if asset_id in visited:
                    continue
                visited.add(asset_id)
                wave.append(asset_id)
            waves.append(wave)
            for completed in wave:
                for dependent in dependents[completed]:
                    remaining_dependencies[dependent].discard(completed)
                    if not remaining_dependencies[dependent]:
                        heapq.heappush(
                            ready,
                            (-self.assets[dependent].risk, dependent),
                        )
        unresolved = sorted(set(self.assets) - visited)
        serial_effort = sum(asset.effort for asset in self.assets.values())
        parallel_effort = sum(
            max((self.assets[asset_id].effort for asset_id in wave), default=0.0)
            for wave in waves
        )
        return {
            "waves": waves,
            "unresolved_cycle_or_missing_dependency": unresolved,
            "serial_effort": serial_effort,
            "parallel_effort": parallel_effort,
            "estimated_reduction_pct": (
                100.0 * (1.0 - parallel_effort / serial_effort)
                if serial_effort
                else 0.0
            ),
            "generated_at": time.time(),
        }
