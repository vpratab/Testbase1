"""Seven mission-specific designs compiled from the two assurance philosophies."""

from __future__ import annotations

from .contracts import (
    ActionMode,
    EvidenceSemantics,
    FailurePosture,
    TopicDesign,
)


TOPIC_DESIGNS: dict[str, TopicDesign] = {
    "QSPARX": TopicDesign(
        topic="QSPARX",
        product_family="AssureEdge Cyber",
        mission_question=(
            "Which cryptographic dependencies create the greatest quantum-era "
            "mission risk, and what migration order reduces risk without breaking "
            "legacy operations?"
        ),
        action_mode=ActionMode.MIGRATE,
        failure_posture=FailurePosture.ADVISORY_ONLY,
        input_contract=(
            "software and configuration artifacts",
            "certificate and key metadata",
            "protocol observations",
            "asset dependencies",
            "mission criticality and data lifetime",
        ),
        maintained_state=(
            "cryptographic bill of materials",
            "dependency graph",
            "algorithm and key posture",
            "quantum exposure score",
            "migration wave state",
            "compliance evidence lineage",
        ),
        decision_contract=(
            "asset_id",
            "risk_score",
            "risk_factors",
            "migration_target",
            "migration_wave",
            "dependency_impact",
        ),
        evidence=EvidenceSemantics(
            proves=(
                "what cryptographic material was observed",
                "which risk basis produced the recommendation",
                "which dependency ordering constrained migration",
            ),
            excludes=(
                "proof that an unscanned asset does not exist",
                "FIPS validation of the chosen implementation",
            ),
            retention="retain inventory hashes and recommendations, not private keys",
            verifier="cyber assessor or migration authority",
        ),
        primary_metrics=(
            "inventory coverage",
            "risk classification precision and recall",
            "discovery latency",
            "migration dependency conflicts",
            "PQC operation latency",
        ),
        philosophy_mapping=(
            "PZDR minimizes retained secrets while preserving audit evidence",
            "RTVLAS treats weak cryptographic indicators as accumulated mission risk",
            "recommendations are evidence-bound rather than opaque scores",
        ),
        known_boundary=(
            "requires enterprise discovery connectors",
            "does not replace cryptographic module validation",
        ),
    ),
    "NV059": TopicDesign(
        topic="NV059",
        product_family="AssureEdge Cyber",
        mission_question=(
            "May this exact subject and device perform this exact action on this "
            "combat-data object now, including while disconnected?"
        ),
        action_mode=ActionMode.AUTHORIZE,
        failure_posture=FailurePosture.FAIL_CLOSED,
        input_contract=(
            "credential chain and proof of key possession",
            "subject clearance, role, and compartments",
            "device attestation and health",
            "data object, action, and protocol",
            "network state and bounded trust lease",
            "behavioral access evidence",
        ),
        maintained_state=(
            "signed policy version",
            "identity and revocation snapshot",
            "bounded offline trust lease",
            "per-subject behavioral baseline",
            "decision receipt chain",
        ),
        decision_contract=(
            "request_id",
            "subject_id",
            "resource_id",
            "action",
            "allowed",
            "reasons",
            "policy_version",
            "offline_authority",
        ),
        evidence=EvidenceSemantics(
            proves=(
                "which identity, posture, policy, and behavior caused the decision",
                "that the decision was not altered after issuance",
            ),
            excludes=(
                "proof that the endpoint remains uncompromised after the decision",
                "network isolation unless an enforcement adapter confirms it",
            ),
            retention="retain decision attributes and hashes, not protected data",
            verifier="security operator, auditor, or downstream combat service",
        ),
        primary_metrics=(
            "false allow and false deny rate",
            "authorization latency",
            "DDIL decision availability",
            "stale-trust rejection",
            "protocol enforcement coverage",
        ),
        philosophy_mapping=(
            "PZDR provides minimal-disclosure signed transaction receipts",
            "RTVLAS contributes persistence against low-and-slow access misuse",
            "offline authority is explicit and expires rather than becoming implicit trust",
        ),
        known_boundary=(
            "requires real ICAM and segmentation integrations",
            "local decisions cannot establish remote endpoint integrity",
        ),
    ),
    "NV062": TopicDesign(
        topic="NV062",
        product_family="AssureEdge Cyber",
        mission_question=(
            "Can a purpose-bound government collection task cross a commercial "
            "boundary confidentially, authentically, quickly, and with replay-safe "
            "return evidence?"
        ),
        action_mode=ActionMode.BROKER,
        failure_posture=FailurePosture.QUARANTINE_TRANSACTION,
        input_contract=(
            "government task intent and classification boundary",
            "commercial provider schema",
            "provider and government cryptographic identities",
            "collection window and area commitment",
            "return-data expectation",
        ),
        maintained_state=(
            "single-use purpose-bound intent",
            "provider adapter state",
            "hybrid classical/PQC session",
            "replay set",
            "task and return receipt chain",
        ),
        decision_contract=(
            "task_id",
            "purpose",
            "provider_adapter",
            "delivery_status",
            "return_status",
            "replay_status",
            "cryptographic_profile",
        ),
        evidence=EvidenceSemantics(
            proves=(
                "the encrypted task matched the authorized purpose",
                "the provider return corresponds to the same task",
                "duplicate task use was rejected",
            ),
            excludes=(
                "proof of satellite execution without provider evidence",
                "IL-5 or IL-6 accreditation",
            ),
            retention="retain commitments and receipts; minimize task plaintext",
            verifier="government task broker and commercial provider gateway",
        ),
        primary_metrics=(
            "bidirectional transaction success",
            "tamper and replay rejection",
            "provider-adapter coverage",
            "round-trip latency",
            "workflow-time reduction",
        ),
        philosophy_mapping=(
            "PZDR turns a sensitive task into a purpose-bound minimal-retention transaction",
            "RTVLAS treats provider workflow state as an observable sequence with anomaly evidence",
            "every boundary crossing produces independently verifiable receipts",
        ),
        known_boundary=(
            "requires a real provider API and accreditation path",
            "cryptographic receipt is not proof of collection",
        ),
    ),
    "NP002": TopicDesign(
        topic="NP002",
        product_family="RTVLAS Mission Assurance",
        mission_question=(
            "Do noisy, intermittently observed UAS tracks collectively exhibit a "
            "persistent formation behavior consistent with escalating threat?"
        ),
        action_mode=ActionMode.ESCALATE,
        failure_posture=FailurePosture.FLAG_AND_CONTINUE,
        input_contract=(
            "timestamped UAS detections",
            "position, velocity, and uncertainty",
            "track association confidence",
            "protected-area geometry",
            "optional type, payload, RF, or imagery evidence",
        ),
        maintained_state=(
            "multi-target custody hypotheses",
            "swarm centroid and spread",
            "formation coherence and contraction",
            "member orientation and acceleration",
            "persistent intent evidence",
        ),
        decision_contract=(
            "swarm_id",
            "risk_level",
            "confidence",
            "dominant_behavior",
            "affected_asset",
            "custody_quality",
            "recommended_escalation",
        ),
        evidence=EvidenceSemantics(
            proves=(
                "which track geometry and persistence caused escalation",
                "how missed detections and custody uncertainty affected confidence",
            ),
            excludes=(
                "UAS payload identity without a classifier",
                "authority to neutralize a target",
            ),
            retention="retain compact track features and alert evidence, not raw imagery by default",
            verifier="C-UAS operator or protective-measure controller",
        ),
        primary_metrics=(
            "track association accuracy",
            "swarm behavior F1",
            "false escalation rate",
            "detection delay",
            "UAS count and clutter scalability",
        ),
        philosophy_mapping=(
            "RTVLAS elevates formation behavior only after persistent contradictions",
            "custody uncertainty lowers confidence instead of disappearing",
            "PZDR evidence enables compact, tamper-evident post-event review",
        ),
        known_boundary=(
            "requires a real detection and identification front end",
            "behavior inference is not target identity",
        ),
    ),
    "NV061": TopicDesign(
        topic="NV061",
        product_family="RTVLAS Mission Assurance",
        mission_question=(
            "Where will each object probably be, how sure are we that it is the "
            "same object, and which uncertain forecast deserves analyst attention?"
        ),
        action_mode=ActionMode.PRIORITIZE,
        failure_posture=FailurePosture.PRESERVE_CUSTODY,
        input_contract=(
            "heterogeneous object observations",
            "sensor uncertainty and source identity",
            "track association candidates",
            "historical local behavior",
            "mission threat and protected-area context",
        ),
        maintained_state=(
            "object state and covariance",
            "multi-source custody confidence",
            "future-state forecast distribution",
            "behavior-change evidence",
            "priority history and analyst disposition",
        ),
        decision_contract=(
            "object_id",
            "forecast_state",
            "forecast_uncertainty",
            "custody_confidence",
            "priority_level",
            "priority_reasons",
            "recommended_investigation",
        ),
        evidence=EvidenceSemantics(
            proves=(
                "which forecast, uncertainty, behavior, and custody produced ranking",
                "whether priority changed due to risk or reduced confidence",
            ),
            excludes=(
                "perfect identity across unobserved intervals",
                "intent inferred solely from kinematics",
            ),
            retention="retain compact state/covariance and ranking evidence",
            verifier="Maritime Targeting Cell analyst or downstream tracker",
        ),
        primary_metrics=(
            "forecast error",
            "track custody accuracy",
            "priority recall",
            "false prioritization rate",
            "objects processed per update",
        ),
        philosophy_mapping=(
            "RTVLAS supplies prediction, covariance, persistence, and explicit uncertainty",
            "weak custody reduces priority confidence instead of being hidden",
            "PZDR receipts preserve why analysts were directed to one object",
        ),
        known_boundary=(
            "requires broader sensor and identity data",
            "kinematic forecast is not a complete adversary intent model",
        ),
    ),
    "NV063": TopicDesign(
        topic="NV063",
        product_family="RTVLAS Mission Assurance",
        mission_question=(
            "Is this local air or surface contact persistently out of family for "
            "the current operating context despite limited historical storage?"
        ),
        action_mode=ActionMode.ESCALATE,
        failure_posture=FailurePosture.FLAG_AND_CONTINUE,
        input_contract=(
            "AIS and ADS-B reports",
            "organic radar or composite tracks",
            "system track number",
            "local route and motion context",
            "cooperative-identification continuity",
        ),
        maintained_state=(
            "compact per-track motion model",
            "compressed route primitives",
            "persistent speed, heading, closing, and identity residuals",
            "watch and high-confidence alert state",
        ),
        decision_contract=(
            "system_track_number",
            "alert_tier",
            "confidence",
            "dominant_deviation",
            "track_details",
            "local_context",
            "operator_action",
        ),
        evidence=EvidenceSemantics(
            proves=(
                "which local baseline and persistent deviation caused the alert",
                "which data-quality screen was applied",
            ),
            excludes=(
                "malicious intent from anomaly alone",
                "global completeness of the local Pattern of Life",
            ),
            retention="retain compact route/motion state and alert evidence, not global raw history",
            verifier="SSDS watchstander or decision-support service",
        ),
        primary_metrics=(
            "alert precision, recall, and F1",
            "watch and high-confidence false-alert rates",
            "detection delay",
            "bytes of state per track",
            "track updates per second",
        ),
        philosophy_mapping=(
            "RTVLAS online calibration learns local normal without a global archive",
            "persistent evidence separates temporary maneuver from sustained deviation",
            "PZDR receipts make machine reasoning reviewable without retaining all raw traffic",
        ),
        known_boundary=(
            "anomaly does not establish hostility",
            "requires ADS-B and SSDS composite-track evaluation",
        ),
    ),
    "NV065": TopicDesign(
        topic="NV065",
        product_family="RTVLAS Mission Assurance",
        mission_question=(
            "Which sensor task contributes the least additional track information, "
            "and where would that finite resource create greater mission value?"
        ),
        action_mode=ActionMode.ADVISORY,
        failure_posture=FailurePosture.ADVISORY_ONLY,
        input_contract=(
            "composite-track covariance and quality",
            "sensor measurement uncertainty",
            "task mode, capacity, cost, and conflicts",
            "track hostility and mission priority",
            "controllable search, cueing, tracking, and illumination options",
        ),
        maintained_state=(
            "sensor-track contribution matrix",
            "diminishing-return state",
            "resource conflicts",
            "candidate task utility",
            "recommendation history and operator disposition",
        ),
        decision_contract=(
            "sensor_id",
            "released_task",
            "recommended_task",
            "affected_track",
            "marginal_information_gain",
            "conflict_penalty",
            "explanation",
        ),
        evidence=EvidenceSemantics(
            proves=(
                "the estimated marginal track-quality contribution",
                "why the alternative task had greater weighted mission value",
            ),
            excludes=(
                "actual radar performance beyond the supplied model",
                "authority to retask sensors automatically",
            ),
            retention="retain recommendation inputs, utility, and operator response",
            verifier="sensor manager, combat-system operator, or resource allocator",
        ),
        primary_metrics=(
            "track-quality improvement",
            "novel-threat response",
            "resource conflicts avoided",
            "recommendation latency",
            "operator acceptance and override rate",
        ),
        philosophy_mapping=(
            "RTVLAS covariance becomes marginal evidence value rather than a trust score",
            "persistent priority changes prevent task thrashing",
            "PZDR receipts preserve exactly why scarce sensor time was moved",
        ),
        known_boundary=(
            "requires traceable program-of-record sensor models",
            "Phase I recommendations remain advisory",
        ),
    ),
}


def get_topic_design(topic: str) -> TopicDesign:
    design = TOPIC_DESIGNS[topic]
    design.validate()
    return design


def validate_design_set() -> None:
    fingerprints = set()
    mission_questions = set()
    for design in TOPIC_DESIGNS.values():
        design.validate()
        if design.fingerprint in fingerprints:
            raise ValueError("topic designs must not be clones")
        if design.mission_question in mission_questions:
            raise ValueError("topic mission questions must be distinct")
        fingerprints.add(design.fingerprint)
        mission_questions.add(design.mission_question)


validate_design_set()
