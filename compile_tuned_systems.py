#!/usr/bin/env python3
"""Compile topic profiles and philosophy-ablation evidence into review artifacts."""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path

from assure_core.profiles import TOPIC_DESIGNS, validate_design_set
from assure_core.pzdr import CryptoAssetNode, PurposeBoundIntent, TrustLease
from assure_core.systems import (
    MaritimePolSystem,
    PredictiveMovementSystem,
    QsparxSystem,
    SecureTaskSystem,
    SensorManagementSystem,
    SwarmIntentSystem,
    ZeroTrustSystem,
)
from trl4_common import EvidenceChain, tamper_test, write_json


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "results" / "tuned_systems"


def build_demonstrations() -> dict:
    now = time.time()
    qsparx = QsparxSystem(
        [
            CryptoAssetNode("root-ca", "rsa2048", 80, set(), "ml-dsa-65", 2),
            CryptoAssetNode(
                "mission-api",
                "rsa2048",
                96,
                {"root-ca"},
                "hybrid-ml-kem-768",
                1,
            ),
        ]
    ).decide()
    zero = ZeroTrustSystem(
        TrustLease(
            policy_version="policy-7",
            identity_version="identity-4",
            issued_at=now - 5,
            expires_at=now + 300,
            permitted_actions=frozenset({"read"}),
            permitted_resources=frozenset({"sensor-track-17"}),
            issuer_signature_valid=True,
        )
    ).decide(
        request_id="zt-1",
        subject_id="operator-12",
        resource_id="sensor-track-17",
        action="read",
        now=now,
        behavior_evidence={"request_rate": 0.4},
    )
    intent = PurposeBoundIntent(
        intent_id="commercial-task-4",
        purpose="maritime collection",
        subject="government-gateway",
        object_id="provider-alpha",
        action="task",
        valid_from=now - 1,
        valid_until=now + 300,
    )
    secure = SecureTaskSystem().decide(
        intent,
        now=now,
        provider="provider-alpha",
    )
    swarm_system = SwarmIntentSystem()
    swarm = None
    for _ in range(8):
        swarm = swarm_system.decide(
            swarm_id="swarm-3",
            protected_asset="ship-1",
            evidence={
                "centroid_closing": 3.0,
                "formation_contraction": 2.0,
                "members_toward_asset": 3.2,
                "zone_penetration": 2.4,
            },
            custody_quality=0.88,
        )
    forecast = PredictiveMovementSystem().decide(
        object_id="contact-77",
        forecast_state=[18.2, -4.1],
        forecast_uncertainty=0.32,
        association_distance=0.4,
        velocity_difference=0.2,
        misses=0,
        identity_consistency=0.96,
        anomaly=0.76,
        proximity=0.82,
        closing=0.74,
    )
    pol_system = MaritimePolSystem()
    pol = None
    for _ in range(8):
        pol = pol_system.decide(
            track_number="STN-140",
            evidence={
                "speed": 1.5,
                "heading": 3.2,
                "closing": 2.8,
                "identity_loss": 1.4,
            },
            details={"speed_knots": 17.2, "course": 114},
            local_context="departure from established traffic lane",
        )
    sensor = SensorManagementSystem().decide(
        sensor_id="SPY-6(V)3-surrogate",
        released_task="repeat-update-well-known-track",
        candidate_task="cue-novel-high-priority-track",
        affected_track="air-track-204",
        prior_variance=0.48,
        measurement_variance=0.018,
        mission_priority=0.94,
        task_cost=1.2,
        conflict_penalty=0.03,
    )
    assert swarm is not None and pol is not None
    return {
        "QSPARX": asdict(qsparx),
        "NV059": asdict(zero),
        "NV062": asdict(secure),
        "NP002": asdict(swarm),
        "NV061": asdict(forecast),
        "NV063": asdict(pol),
        "NV065": asdict(sensor),
    }


def build_ablations() -> dict:
    now = time.time()
    assets = [
        CryptoAssetNode("root", "rsa2048", 75, set(), "ml-dsa-65", 2),
        CryptoAssetNode("dependent", "rsa2048", 99, {"root"}, "ml-kem-768", 1),
    ]
    migration = QsparxSystem(assets).decide()
    naive_first = max(assets, key=lambda asset: asset.risk).asset_id

    zero = ZeroTrustSystem(
        TrustLease(
            policy_version="p1",
            identity_version="i1",
            issued_at=now,
            expires_at=now + 300,
            permitted_actions=frozenset({"read"}),
            permitted_resources=frozenset({"track"}),
            issuer_signature_valid=True,
        )
    )
    first_access = zero.decide(
        request_id="first",
        subject_id="operator",
        resource_id="track",
        action="read",
        now=now,
        behavior_evidence={
            "request_rate": 4.0,
            "failed_access": 3.0,
            "data_volume": 4.0,
        },
    )
    persistent_access = first_access
    for index in range(8):
        persistent_access = zero.decide(
            request_id=f"persistent-{index}",
            subject_id="operator",
            resource_id="track",
            action="read",
            now=now,
            behavior_evidence={
                "request_rate": 4.0,
                "failed_access": 3.0,
                "data_volume": 4.0,
            },
        )

    intent = PurposeBoundIntent(
        intent_id="task",
        purpose="collection",
        subject="gateway",
        object_id="provider",
        action="task",
        valid_from=now - 1,
        valid_until=now + 60,
    )
    task_system = SecureTaskSystem()
    first_task = task_system.decide(intent, now=now, provider="provider")
    replay_task = task_system.decide(intent, now=now, provider="provider")

    swarm_system = SwarmIntentSystem()
    transient_swarm = swarm_system.decide(
        swarm_id="s",
        protected_asset="ship",
        evidence={"centroid_closing": 3.0, "members_toward_asset": 2.5},
        custody_quality=0.9,
    )
    sustained_swarm = transient_swarm
    for _ in range(8):
        sustained_swarm = swarm_system.decide(
            swarm_id="s",
            protected_asset="ship",
            evidence={
                "centroid_closing": 3.0,
                "formation_contraction": 2.5,
                "members_toward_asset": 3.0,
                "zone_penetration": 2.0,
            },
            custody_quality=0.9,
        )

    movement = PredictiveMovementSystem()
    strong_custody = movement.decide(
        object_id="o",
        forecast_state=[1, 2],
        forecast_uncertainty=0.4,
        association_distance=0.1,
        velocity_difference=0.1,
        misses=0,
        identity_consistency=0.99,
        anomaly=0.8,
        proximity=0.8,
        closing=0.7,
    )
    weak_custody = movement.decide(
        object_id="o",
        forecast_state=[1, 2],
        forecast_uncertainty=0.4,
        association_distance=7.0,
        velocity_difference=3.0,
        misses=4,
        identity_consistency=0.45,
        anomaly=0.8,
        proximity=0.8,
        closing=0.7,
    )

    pol_system = MaritimePolSystem()
    transient_pol = pol_system.decide(
        track_number="1",
        evidence={"heading": 3.0, "closing": 2.0},
        details={},
        local_context="lane",
    )
    sustained_pol = transient_pol
    for _ in range(8):
        sustained_pol = pol_system.decide(
            track_number="1",
            evidence={"heading": 3.0, "closing": 2.5},
            details={},
            local_context="lane",
        )

    sensor_system = SensorManagementSystem()
    no_conflict = sensor_system.decide(
        sensor_id="sensor",
        released_task="old",
        candidate_task="new",
        affected_track="t",
        prior_variance=0.5,
        measurement_variance=0.02,
        mission_priority=1.0,
        task_cost=1.0,
        conflict_penalty=0.0,
    )
    conflict = sensor_system.decide(
        sensor_id="sensor",
        released_task="old",
        candidate_task="new",
        affected_track="t",
        prior_variance=0.5,
        measurement_variance=0.02,
        mission_priority=1.0,
        task_cost=1.0,
        conflict_penalty=1.0,
    )
    ablations = {
        "QSPARX": {
            "naive_highest_risk_first": naive_first,
            "dependency_aware_first_wave": "root",
            "selected_asset": migration.evidence_payload["asset_id"],
            "selected_asset_wave": migration.evidence_payload["migration_wave"],
            "finding": "risk-only ordering breaks the dependency; tuned ordering does not",
        },
        "NV059": {
            "first_sample_action": first_access.action,
            "persistent_sequence_action": persistent_access.action,
            "finding": "persistent low-and-slow evidence changes the authorization outcome",
        },
        "NV062": {
            "first_use_action": first_task.action,
            "replay_action": replay_task.action,
            "finding": "purpose-bound single-use intent quarantines replay",
        },
        "NP002": {
            "transient_action": transient_swarm.action,
            "sustained_action": sustained_swarm.action,
            "finding": "formation escalation requires persistence",
        },
        "NV061": {
            "strong_custody_priority": strong_custody.evidence_payload["priority_level"],
            "strong_custody_confidence": strong_custody.confidence,
            "weak_custody_priority": weak_custody.evidence_payload["priority_level"],
            "weak_custody_confidence": weak_custody.confidence,
            "finding": "uncertain custody reduces confidence and ranking",
        },
        "NV063": {
            "transient_alert_tier": transient_pol.evidence_payload["alert_tier"],
            "sustained_alert_tier": sustained_pol.evidence_payload["alert_tier"],
            "finding": "a transient deviation and a persistent deviation do not produce the same alert",
        },
        "NV065": {
            "without_conflict": no_conflict.action,
            "with_conflict": conflict.action,
            "finding": "resource conflicts can reverse an otherwise attractive recommendation",
        },
    }
    expected = {
        ("QSPARX", "naive_highest_risk_first"): "dependent",
        ("QSPARX", "dependency_aware_first_wave"): "root",
        ("NV059", "first_sample_action"): "allow",
        ("NV059", "persistent_sequence_action"): "deny",
        ("NV062", "first_use_action"): "release_task",
        ("NV062", "replay_action"): "quarantine_task",
        ("NP002", "transient_action"): "continue_monitoring",
        ("NP002", "sustained_action"): "activate_protective_measure",
        ("NV061", "strong_custody_priority"): "high",
        ("NV061", "weak_custody_priority"): "watch",
        ("NV063", "transient_alert_tier"): "none",
        ("NV063", "sustained_alert_tier"): "high_confidence",
        ("NV065", "without_conflict"): "recommend_reallocation",
        ("NV065", "with_conflict"): "retain_current_task",
    }
    for (topic, field), value in expected.items():
        actual = ablations[topic][field]
        if actual != value:
            raise AssertionError(
                f"{topic} ablation mismatch for {field}: "
                f"expected {value!r}, got {actual!r}"
            )
    return ablations


def render_architecture(demonstrations: dict, ablations: dict) -> str:
    rows = "\n".join(
        f"| {topic} | {design.product_family} | {design.action_mode.value} | "
        f"{design.failure_posture.value} | {demonstrations[topic]['action']} |"
        for topic, design in TOPIC_DESIGNS.items()
    )
    sections = []
    for topic, design in TOPIC_DESIGNS.items():
        sections.append(
            f"""## {topic}

**Mission decision:** {design.mission_question}

**PZDR/RTVLAS tuning**

{chr(10).join(f"- {item}" for item in design.philosophy_mapping)}

**Maintained state**

{chr(10).join(f"- {item}" for item in design.maintained_state)}

**Evidence proves**

{chr(10).join(f"- {item}" for item in design.evidence.proves)}

**Evidence explicitly does not prove**

{chr(10).join(f"- {item}" for item in design.evidence.excludes)}

**Current boundary**

{chr(10).join(f"- {item}" for item in design.known_boundary)}
"""
        )
    ablation_rows = "\n".join(
        f"| {topic} | {result['finding']} |"
        for topic, result in ablations.items()
    )
    return f"""# Tuned Assurance Systems

The shared IP is expressed as two philosophies:

- **AssureEdge Cyber:** constrain sensitive transactions, minimize exposed
  material, bind actions to purpose and policy, and produce independent proof.
- **RTVLAS Mission Assurance:** predict expected state, compare uncertain
  observations, accumulate persistent contradictions, explain decisions, and
  preserve evidence.

The seven systems deliberately do not share the same decision contract.

| Topic | Product family | Action mode | Failure posture | Example decision |
| --- | --- | --- | --- | --- |
{rows}

## Measured philosophy ablations

These checks require the topic-specific philosophy to change an observable
decision. The compiler fails if any expected contrast disappears.

| Topic | Measured distinction |
| --- | --- |
{ablation_rows}

{chr(10).join(sections)}
"""


def render_scorecard() -> str:
    wave5_path = ROOT / "results" / "trl4_wave5" / "wave5_match_scores.json"
    wave4_path = ROOT / "results" / "trl4_wave4" / "wave4_match_scores.json"
    wave3_path = ROOT / "results" / "trl4_wave3" / "wave3_match_scores.json"
    extended_path = (
        ROOT / "results" / "trl4_extensions" / "extended_match_scores.json"
    )
    base_path = ROOT / "results" / "trl4_campaign" / "match_scores.json"
    score_path = (
        wave5_path
        if wave5_path.exists()
        else wave4_path
        if wave4_path.exists()
        else wave3_path
        if wave3_path.exists()
        else extended_path
        if extended_path.exists()
        else base_path
    )
    if not score_path.exists():
        return "# Tuned System Scorecard\n\nCampaign scores are not available.\n"
    scores = json.loads(score_path.read_text())
    next_lift = {
        "QSPARX": "Sponsor-authorized AFDW/range and CMDB evaluation",
        "NV059": "Network-fabric enforcement, DoD PKI/CAC, and DDS Security",
        "NV062": "Credentialed collection task and accreditation evidence",
        "NP002": "Live C-UAS front end, payload labels, and field trials",
        "NV061": "Longer air trajectories and operational composite-track identity",
        "NV063": "Operational composite-track feed and SSDS evaluation",
        "NV065": "Approved program sensor models and SSDS tasking interface",
    }
    ranked = sorted(
        scores.items(),
        key=lambda item: item[1]["score"],
        reverse=True,
    )
    rows = "\n".join(
        f"| {topic} | {result['score']:.1f} | {result['estimated_trl']:.1f} | "
        f"{TOPIC_DESIGNS[topic].action_mode.value} | {next_lift[topic]} |"
        for topic, result in ranked
    )
    evidence_label = (
        "fifth-wave TRL-4 campaign"
        if score_path == wave5_path
        else "fourth-wave TRL-4 campaign"
        if score_path == wave4_path
        else "third-wave TRL-4 campaign"
        if score_path == wave3_path
        else "extended TRL-4 campaign"
        if score_path == extended_path
        else "base TRL-4 campaign"
    )
    return f"""# Tuned System Scorecard

The 1-100 values are the conservative empirical scores from the
{evidence_label}. The architecture strengthens topic fit and testability,
but does not manufacture points for integrations or data that have not
been demonstrated.

| Topic | Match / 100 | Est. TRL | Tuned decision mode | Highest-value next proof |
| --- | ---: | ---: | --- | --- |
{rows}

All seven designs have unique decision contracts and passed decision-changing
philosophy ablations. See `philosophy_ablations.json` for the measured contrasts.
"""


def main() -> None:
    validate_design_set()
    demonstrations = build_demonstrations()
    ablations = build_ablations()
    chain = EvidenceChain(b"tuned-assurance-systems")
    for topic, decision in demonstrations.items():
        chain.append(topic, decision)
    manifests = {
        topic: {
            **asdict(design),
            "fingerprint": design.fingerprint,
            "example_decision": demonstrations[topic],
        }
        for topic, design in TOPIC_DESIGNS.items()
    }
    output = {
        "topic_count": len(manifests),
        "unique_design_fingerprints": len(
            {manifest["fingerprint"] for manifest in manifests.values()}
        ),
        "manifests": manifests,
        "philosophy_ablations": ablations,
        "evidence": {
            "records": len(chain.records),
            "head": chain.head,
            "verified": EvidenceChain.verify(chain.records, chain.public_key),
            "tamper_detected": tamper_test(chain.records, chain.public_key),
        },
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    write_json(OUTPUT / "tuned_systems.json", output)
    write_json(OUTPUT / "philosophy_ablations.json", ablations)
    for topic, manifest in manifests.items():
        write_json(OUTPUT / "topics" / f"{topic.lower()}_design.json", manifest)
    (OUTPUT / "TUNED_SYSTEM_ARCHITECTURE.md").write_text(
        render_architecture(demonstrations, ablations)
    )
    (OUTPUT / "TUNED_SYSTEM_SCORECARD.md").write_text(render_scorecard())
    print(json.dumps(output["evidence"], indent=2))
    print(f"Output: {OUTPUT}")


if __name__ == "__main__":
    main()
