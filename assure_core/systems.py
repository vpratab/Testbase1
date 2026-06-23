"""Topic-tuned systems built from the shared assurance primitives."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from .contracts import AssuranceDecision, state_digest
from .profiles import get_topic_design
from .pzdr import (
    CryptoAssetNode,
    MigrationWavePlanner,
    ProcessingReceipt,
    PurposeBoundIntent,
    TrustLease,
)
from .rtvlas import (
    EvidenceChannel,
    SequentialEvidenceAccumulator,
    custody_confidence,
    marginal_information_value,
    priority_score,
)


@dataclass
class QsparxSystem:
    assets: list[CryptoAssetNode]

    def decide(self) -> AssuranceDecision:
        design = get_topic_design("QSPARX")
        plan = MigrationWavePlanner(self.assets).plan(lanes=4)
        highest = max(self.assets, key=lambda asset: asset.risk)
        wave_by_asset = {
            asset_id: index
            for index, wave in enumerate(plan["waves"], start=1)
            for asset_id in wave
        }
        payload = {
            "asset_id": highest.asset_id,
            "risk_score": highest.risk,
            "risk_factors": ["quantum_vulnerable_algorithm", "dependency_exposure"],
            "migration_target": highest.migration_target,
            "migration_wave": wave_by_asset.get(highest.asset_id),
            "dependency_impact": sorted(highest.dependencies),
        }
        decision = AssuranceDecision(
            topic="QSPARX",
            action="prioritize_crypto_migration",
            confidence=min(0.55 + highest.risk / 200.0, 0.99),
            reasons=("highest mission-weighted quantum exposure",),
            state_digest=state_digest(plan),
            evidence_payload=payload,
        )
        decision.validate(design)
        return decision


@dataclass
class ZeroTrustSystem:
    trust_lease: TrustLease
    behavior: SequentialEvidenceAccumulator = field(
        default_factory=lambda: SequentialEvidenceAccumulator(
            (
                EvidenceChannel("request_rate", 1.0, 1.5, 4.0, 9.0),
                EvidenceChannel("failed_access", 1.1, 0.8, 3.0, 7.0),
                EvidenceChannel("data_volume", 0.9, 1.2, 4.0, 10.0),
            )
        )
    )

    def decide(
        self,
        *,
        request_id: str,
        subject_id: str,
        resource_id: str,
        action: str,
        now: float,
        behavior_evidence: dict[str, float],
    ) -> AssuranceDecision:
        design = get_topic_design("NV059")
        lease_allowed, lease_reason = self.trust_lease.authorize(
            now,
            action,
            resource_id,
        )
        behavior = self.behavior.update(behavior_evidence)
        allowed = lease_allowed and behavior["decision"] != "reject"
        reasons = [lease_reason, *behavior["reasons"]]
        payload = {
            "request_id": request_id,
            "subject_id": subject_id,
            "resource_id": resource_id,
            "action": action,
            "allowed": allowed,
            "reasons": reasons,
            "policy_version": self.trust_lease.policy_version,
            "offline_authority": lease_allowed,
        }
        decision = AssuranceDecision(
            topic="NV059",
            action="allow" if allowed else "deny",
            confidence=0.98 if not allowed else 0.90,
            reasons=tuple(reasons),
            state_digest=state_digest(
                {
                    "trust_lease": self.trust_lease,
                    "behavior_scores": behavior["scores"],
                }
            ),
            evidence_payload=payload,
        )
        decision.validate(design)
        return decision


@dataclass
class SecureTaskSystem:
    use_counts: dict[str, int] = field(default_factory=dict)

    def decide(
        self,
        intent: PurposeBoundIntent,
        *,
        now: float,
        provider: str,
    ) -> AssuranceDecision:
        design = get_topic_design("NV062")
        uses = self.use_counts.get(intent.intent_id, 0)
        allowed, reason = intent.permits(
            now=now,
            subject=intent.subject,
            object_id=intent.object_id,
            action=intent.action,
            use_count=uses,
        )
        if allowed:
            self.use_counts[intent.intent_id] = uses + 1
        payload = {
            "task_id": intent.intent_id,
            "purpose": intent.purpose,
            "provider_adapter": provider,
            "delivery_status": "released" if allowed else "quarantined",
            "return_status": "pending" if allowed else "not_expected",
            "replay_status": "first_use" if uses == 0 else "duplicate",
            "cryptographic_profile": "hybrid-ml-kem-768-x25519",
        }
        decision = AssuranceDecision(
            topic="NV062",
            action="release_task" if allowed else "quarantine_task",
            confidence=0.99,
            reasons=(reason,),
            state_digest=state_digest(
                {"intent_commitment": intent.commitment, "uses": uses}
            ),
            evidence_payload=payload,
        )
        decision.validate(design)
        return decision


@dataclass
class SwarmIntentSystem:
    monitor: SequentialEvidenceAccumulator = field(
        default_factory=lambda: SequentialEvidenceAccumulator(
            (
                EvidenceChannel("centroid_closing", 1.0, 0.7, 3.0, 7.5),
                EvidenceChannel("formation_contraction", 0.9, 0.6, 3.0, 7.0),
                EvidenceChannel("members_toward_asset", 1.2, 0.8, 3.5, 7.5),
                EvidenceChannel("zone_penetration", 1.4, 0.5, 2.5, 6.0),
            )
        )
    )

    def decide(
        self,
        *,
        swarm_id: str,
        protected_asset: str,
        evidence: dict[str, float],
        custody_quality: float,
    ) -> AssuranceDecision:
        design = get_topic_design("NP002")
        result = self.monitor.update(evidence)
        confidence = float(
            np.clip(
                (0.45 + min(result["weighted_total"] / 20.0, 0.5))
                * custody_quality,
                0.0,
                1.0,
            )
        )
        payload = {
            "swarm_id": swarm_id,
            "risk_level": result["decision"],
            "confidence": confidence,
            "dominant_behavior": max(evidence, key=evidence.get),
            "affected_asset": protected_asset,
            "custody_quality": custody_quality,
            "recommended_escalation": (
                "cue_additional_sensor"
                if result["decision"] == "flag"
                else "activate_protective_measure"
                if result["decision"] == "reject"
                else "continue_monitoring"
            ),
        }
        decision = AssuranceDecision(
            topic="NP002",
            action=payload["recommended_escalation"],
            confidence=confidence,
            reasons=tuple(result["reasons"]),
            state_digest=state_digest(result["scores"]),
            evidence_payload=payload,
        )
        decision.validate(design)
        return decision


@dataclass
class PredictiveMovementSystem:
    def decide(
        self,
        *,
        object_id: str,
        forecast_state: list[float],
        forecast_uncertainty: float,
        association_distance: float,
        velocity_difference: float,
        misses: int,
        identity_consistency: float,
        anomaly: float,
        proximity: float,
        closing: float,
    ) -> AssuranceDecision:
        design = get_topic_design("NV061")
        custody = custody_confidence(
            association_distance=association_distance,
            velocity_difference=velocity_difference,
            misses=misses,
            identity_consistency=identity_consistency,
        )
        priority = priority_score(
            anomaly=anomaly,
            forecasted_proximity=proximity,
            closing_rate=closing,
            uncertainty=min(forecast_uncertainty, 1.0),
            custody=custody,
        )
        level = (
            "critical"
            if priority >= 0.80
            else "high"
            if priority >= 0.60
            else "watch"
            if priority >= 0.35
            else "routine"
        )
        reasons = (
            "persistent_behavior_change" if anomaly > 0.5 else "stable_behavior",
            "weak_track_custody" if custody < 0.6 else "track_custody_supported",
        )
        payload = {
            "object_id": object_id,
            "forecast_state": forecast_state,
            "forecast_uncertainty": forecast_uncertainty,
            "custody_confidence": custody,
            "priority_level": level,
            "priority_reasons": list(reasons),
            "recommended_investigation": level in {"critical", "high"},
        }
        decision = AssuranceDecision(
            topic="NV061",
            action=f"rank_{level}",
            confidence=0.55 + 0.45 * custody,
            reasons=reasons,
            state_digest=state_digest(payload),
            evidence_payload=payload,
        )
        decision.validate(design)
        return decision


@dataclass
class MaritimePolSystem:
    monitor: SequentialEvidenceAccumulator = field(
        default_factory=lambda: SequentialEvidenceAccumulator(
            (
                EvidenceChannel("speed", 0.9, 1.2, 4.0, 9.0),
                EvidenceChannel("heading", 1.0, 1.0, 4.0, 8.0),
                EvidenceChannel("closing", 1.1, 0.8, 3.5, 7.5),
                EvidenceChannel("identity_loss", 1.5, 0.4, 2.0, 5.0),
            )
        )
    )

    def decide(
        self,
        *,
        track_number: str,
        evidence: dict[str, float],
        details: dict[str, Any],
        local_context: str,
    ) -> AssuranceDecision:
        design = get_topic_design("NV063")
        result = self.monitor.update(evidence)
        tier = (
            "high_confidence"
            if result["decision"] == "reject"
            else "watch"
            if result["decision"] == "flag"
            else "none"
        )
        confidence = float(
            np.clip(0.40 + result["weighted_total"] / 24.0, 0.0, 0.99)
        )
        payload = {
            "system_track_number": track_number,
            "alert_tier": tier,
            "confidence": confidence,
            "dominant_deviation": max(evidence, key=evidence.get),
            "track_details": details,
            "local_context": local_context,
            "operator_action": (
                "increase_scrutiny"
                if tier == "watch"
                else "resolve_identity_and_cue_sensor"
                if tier == "high_confidence"
                else "none"
            ),
        }
        decision = AssuranceDecision(
            topic="NV063",
            action=payload["operator_action"],
            confidence=confidence,
            reasons=tuple(result["reasons"]),
            state_digest=state_digest(result["scores"]),
            evidence_payload=payload,
        )
        decision.validate(design)
        return decision


@dataclass
class SensorManagementSystem:
    def decide(
        self,
        *,
        sensor_id: str,
        released_task: str,
        candidate_task: str,
        affected_track: str,
        prior_variance: float,
        measurement_variance: float,
        mission_priority: float,
        task_cost: float,
        conflict_penalty: float,
    ) -> AssuranceDecision:
        design = get_topic_design("NV065")
        value = marginal_information_value(
            prior_variance=prior_variance,
            measurement_variance=measurement_variance,
            mission_priority=mission_priority,
            task_cost=task_cost,
            conflict_penalty=conflict_penalty,
        )
        recommend = value["utility"] > 0
        payload = {
            "sensor_id": sensor_id,
            "released_task": released_task if recommend else None,
            "recommended_task": candidate_task if recommend else None,
            "affected_track": affected_track,
            "marginal_information_gain": value["information_gain"],
            "conflict_penalty": conflict_penalty,
            "explanation": (
                "candidate task has positive mission-weighted marginal information value"
                if recommend
                else "candidate task does not exceed conflict-adjusted release value"
            ),
        }
        decision = AssuranceDecision(
            topic="NV065",
            action="recommend_reallocation" if recommend else "retain_current_task",
            confidence=float(np.clip(abs(value["utility"]) * 4.0, 0.45, 0.98)),
            reasons=(payload["explanation"],),
            state_digest=state_digest(value),
            evidence_payload=payload,
        )
        decision.validate(design)
        return decision


def make_processing_receipt(
    *,
    operation_id: str,
    input_payload: bytes,
    output_payload: bytes,
    policy_version: str,
    code_identity: str,
    result: str,
) -> ProcessingReceipt:
    now = time.time()
    return ProcessingReceipt(
        operation_id=operation_id,
        input_commitment=hashlib.sha384(input_payload).hexdigest(),
        output_commitment=hashlib.sha384(output_payload).hexdigest(),
        policy_version=policy_version,
        code_identity=code_identity,
        started_at=now,
        completed_at=time.time(),
        ephemeral_material_destroyed=True,
        result=result,
    )
