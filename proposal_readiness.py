#!/usr/bin/env python3
"""Generate topic-level Phase I proposal packets from the evidence base."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "results" / "proposal_readiness"


TOPICS: dict[str, dict[str, Any]] = {
    "NV059": {
        "status": "GO",
        "readiness_score": 88,
        "plain_need": "Control who and what can access combat-system data in real time, even under degraded connectivity.",
        "phase_i_hypothesis": "Purpose-bound zero-trust enforcement can keep compartmented data usable while rejecting stale, replayed, revoked, and wrong-purpose access.",
        "proposal_claim": "We will demonstrate a combat-system zero-trust access layer with bounded native decisions, protocol adapters, DDIL leases, and signed evidence receipts.",
        "strongest_evidence": [
            "secure OPC UA and Cyclone DDS authorization tests",
            "mTLS microsegmentation and Modbus/TCP surrogate paths",
            "native microsecond-scale decision primitives",
            "replay, revocation, compartment, and DDIL negative tests",
        ],
        "primary_artifacts": [
            "results/trl4_wave4/wave4_campaign_results.json",
            "results/trl4_wave5/wave5_campaign_results.json",
            "results/independent_benchmark/INDEPENDENT_BENCHMARK.md",
        ],
        "first_month_proof": "Freeze the identity, compartment, protocol, DDIL, and latency test matrix with sponsor-approved policy cases.",
        "phase_i_base_demo": "Run the enforcement point against representative authorized and unauthorized transactions and report latency, availability, false denial, replay rejection, and audit evidence.",
        "phase_i_option_demo": "Integrate sponsor-provided identities or a sponsor-approved identity surrogate and exercise a larger combat-network emulation.",
        "failure_condition": "Bypass around the enforcement point, unsafe DDIL policy widening, or unacceptable false denial.",
        "do_not_overclaim": "The lab is not an accredited combat network and does not prove production DoD identity integration.",
        "external_access_request": "test identities, compartment/purpose matrix, representative policy decisions, two or more network segments, and protocol endpoints",
    },
    "NV061": {
        "status": "GO",
        "readiness_score": 88,
        "plain_need": "Track many maritime objects, predict future movement, preserve identity, and prioritize what analysts should look at first.",
        "phase_i_hypothesis": "Calibrated forecasting plus custody-aware priority can reduce analyst load while preserving uncertainty and identity ambiguity.",
        "proposal_claim": "We will demonstrate future-state prediction, custody-aware hierarchy, dense-crossing identity stress, and cross-region public-data transfer evidence.",
        "strongest_evidence": [
            "frozen Puget-to-New-York forecast transfer improved over hold by 20.8%",
            "custody-aware dense crossing improved 256-object accuracy from 57.4% to 85.2%",
            "identity switches dropped 56.8% in the dense-crossing campaign",
            "native sparse association and authenticated track frame benchmarks",
        ],
        "primary_artifacts": [
            "results/frozen_region/frozen_region_results.json",
            "results/dense_crossing/dense_crossing_results.json",
            "results/trl4_wave5/EVIDENCE_INDEX.md",
        ],
        "first_month_proof": "Freeze track, custody, forecast, priority, analyst-time, and scale metrics with any sponsor-provided composite-track examples.",
        "phase_i_base_demo": "Evaluate prediction and priority on public plus sponsor-approved tracks, including failure cases for identity ambiguity and missed detections.",
        "phase_i_option_demo": "Run on de-identified composite tracks with analyst priority dispositions if available.",
        "failure_condition": "Loss of calibration, excessive identity switching, or no improvement over analyst workflow or baseline forecasting.",
        "do_not_overclaim": "Public AIS/ADS-B identifiers are not operational intent truth or Navy analyst-priority truth.",
        "external_access_request": "de-identified multi-source tracks with covariance, source, identity continuity events, and analyst priority dispositions",
    },
    "NV065": {
        "status": "GO",
        "readiness_score": 85,
        "plain_need": "Help ship operators decide which sensors should spend limited time on which tasks without degrading important track quality.",
        "phase_i_hypothesis": "Explainable marginal information value can recommend resource release and retasking while respecting hard SSDS-like constraints.",
        "proposal_claim": "We will deliver an operator-advisory scheduler that explains each recommendation, enforces hard task constraints, and measures track-quality utility.",
        "strongest_evidence": [
            "zero invalid schedules in surrogate campaigns",
            "bounded native scheduler timing",
            "beam, dwell, slew, revisit, and operator-advisory contracts",
            "conservative fusion and degradation studies",
        ],
        "primary_artifacts": [
            "results/trl4_wave5/wave5_campaign_results.json",
            "results/performance/native_kernel_scaling.json",
            "docs/TOPIC_TECHNICAL_OBJECTIVES.md",
        ],
        "first_month_proof": "Translate provided sensor/task parameters into hard constraints, deadlines, conflicts, and track-quality utility definitions.",
        "phase_i_base_demo": "Run advisory scheduling on sponsor-approved scenarios and compare nominal, degraded, and conservative-fusion schedules.",
        "phase_i_option_demo": "Profile timing on representative hardware or a sponsor-approved SSDS-like replay harness.",
        "failure_condition": "Track-quality loss, constraint violation, unstable recommendations, missed hard deadlines, or no benefit over current allocation.",
        "do_not_overclaim": "Generic radar and sensor parameters are not SSDS validation or fire-control-quality proof.",
        "external_access_request": "reference combat-system architecture, sensor task parameters, hard conflicts, deadline semantics, and track-quality definitions",
    },
    "NV063": {
        "status": "GO",
        "readiness_score": 83,
        "plain_need": "Notice unusual ship or aircraft behavior in crowded maritime areas without exhausting watchstanders.",
        "phase_i_hypothesis": "Compact pattern-of-life state plus watch/high-confidence alert tiers can control burden while flagging meaningful deviations.",
        "proposal_claim": "We will demonstrate a low-history, explainable alerting method with frozen regional transfer testing and explicit failed single-tier diagnostics.",
        "strongest_evidence": [
            "frozen Puget-to-New-York transfer preserved a usable watch-tier contract",
            "single-tier alert targets failed and remain recorded",
            "high-confidence nominal-proxy alert rate was zero in the New York sample",
            "authenticated composite interface and reason-code evidence",
        ],
        "primary_artifacts": [
            "results/frozen_region/frozen_region_results.json",
            "results/frozen_region/FROZEN_REGION_REPORT.md",
            "docs/DATA_AND_MODEL_CARDS.md",
        ],
        "first_month_proof": "Freeze regional replay, compact-state ceiling, watch budget, high-confidence budget, and operator-disposition protocol.",
        "phase_i_base_demo": "Run regional replay with reason-coded watch and high-confidence tiers, measuring recall, alert burden, delay, and storage.",
        "phase_i_option_demo": "Collect operator dispositions on replayed alerts and tune thresholds only under a documented calibration protocol.",
        "failure_condition": "Alert fatigue, regional brittleness, unexplained alerts, or reliance on impractical historical storage.",
        "do_not_overclaim": "Injected anomalies and nominal proxies are not hostile-behavior labels or operational false-alarm estimates.",
        "external_access_request": "representative regional replay, interface schema, storage ceiling, and operator watch/high-confidence dispositions",
    },
    "NV062": {
        "status": "CONDITIONAL GO",
        "readiness_score": 82,
        "plain_need": "Let government users securely task commercial assets without exposing intent or losing approval, cancellation, return, and retention evidence.",
        "phase_i_hypothesis": "A provider-neutral secure task envelope can preserve purpose, release authority, replay protection, and return-data integrity across commercial interfaces.",
        "proposal_claim": "We will demonstrate provider-neutral secure tasking against public provider schemas, sandbox paths, lifecycle states, and verified returns.",
        "strongest_evidence": [
            "Capella live OpenAPI reachability",
            "Umbra production and sandbox tasking endpoint schema conformance",
            "real Capella and Umbra open-data return verification",
            "hybrid task envelopes with replay, tamper, and authorization negative tests",
        ],
        "primary_artifacts": [
            "results/trl4_wave5/wave5_campaign_results.json",
            "results/trl4_wave4/wave4_campaign_results.json",
            "docs/EXTERNAL_ACCESS_PACKAGES.md",
        ],
        "first_month_proof": "Establish provider interface, credential boundary, approval chain, cancellation, return, and retention semantics.",
        "phase_i_base_demo": "Exercise public schemas and simulated sandbox lifecycle with valid and invalid task transactions, return verification, and signed evidence.",
        "phase_i_option_demo": "Complete one credentialed sandbox lifecycle if provider or government boundary approval is available.",
        "failure_condition": "Ambiguous release authority, schema-specific lock-in, inability to maintain end-to-end evidence, or no credible provider sandbox path.",
        "do_not_overclaim": "No live paid collection, IL5/IL6 authorization, or classified tasking authority has been demonstrated.",
        "external_access_request": "sandbox credential guidance, representative task and lifecycle schemas, approval/cancellation states, and return metadata",
    },
    "QSPARX": {
        "status": "CONDITIONAL GO",
        "readiness_score": 81,
        "plain_need": "Find vulnerable cryptography, map dependencies, and plan a safe post-quantum migration without breaking mission systems.",
        "phase_i_hypothesis": "Dependency-aware cryptographic discovery and staged migration can reduce transition breakage while producing measurable PQC readiness.",
        "proposal_claim": "We will demonstrate cryptographic inventory, dependency-safe migration sequencing, rollback checkpoints, and real PQC operations in a sponsor-approved range.",
        "strongest_evidence": [
            "ML-KEM and ML-DSA operations",
            "certificate, PKCS#12, OpenSSH, source, and configuration discovery",
            "dependency-safe migration execution",
            "synthetic 200-asset migration study avoiding break-before-dependency errors",
        ],
        "primary_artifacts": [
            "results/trl4_wave5/wave5_campaign_results.json",
            "results/theory_campaign/theory_campaign_results.json",
            "docs/EXTERNAL_ACCESS_PACKAGES.md",
        ],
        "first_month_proof": "Establish authorized inventory scope, ground-truth subset, dependency graph, and rollback exercise.",
        "phase_i_base_demo": "Inventory a sanitized range, score PQC readiness, build dependency waves, and prove rollback evidence on a representative subset.",
        "phase_i_option_demo": "Exercise legacy interoperability and mission-continuity checks on a sponsor-approved AFDW-like replica.",
        "failure_condition": "Materially incomplete inventory, unresolved dependency cycles, disruptive migration, or no measurable readiness improvement.",
        "do_not_overclaim": "The local enterprise range is not AFDW inventory and is not FIPS-validated cryptographic module operation.",
        "external_access_request": "sanitized asset inventory, cryptographic metadata, dependency edges, key-storage class, and approved migration policy",
    },
    "NP002": {
        "status": "PARTNER GO",
        "readiness_score": 77,
        "plain_need": "Improve defensive detection, identification, tracking, and handoff for small hostile UAS without claiming full defeat authority.",
        "phase_i_hypothesis": "Low-cost multimodal sensing and custody-aware tracking can improve UAS track continuity, identification, and handoff under clutter.",
        "proposal_claim": "We will demonstrate a defensive sensing, track-custody, identification, and handoff module for an existing C-UAS architecture.",
        "strongest_evidence": [
            "NASA UAS acoustic recording-level holdouts",
            "typed tracking and behavior evidence",
            "custody-aware dense-crossing improvement",
            "bounded native tracking primitives and handoff-contract plan",
        ],
        "primary_artifacts": [
            "results/dense_crossing/dense_crossing_results.json",
            "results/trl4_wave4/wave4_campaign_results.json",
            "docs/NP002_FIELD_VALIDATION_PATH.md",
        ],
        "first_month_proof": "Freeze the selected technology lane, target groups, modalities, clutter conditions, field truth, and integration boundary.",
        "phase_i_base_demo": "Replay synchronized or sponsor-approved sensor data and measure detection, classification, track continuity, identity switches, and latency.",
        "phase_i_option_demo": "Support controlled field collection or demonstrate non-authoritative handoff to an existing defensive C-UAS system.",
        "failure_condition": "Modality collapse, excessive clutter false alarms, loss of custody at scale, hardware resource overrun, or no integration owner.",
        "do_not_overclaim": "The current work is not a full Detect-Track-Identify-Assess-Neutralize chain and does not control defeat effects.",
        "external_access_request": "synchronized radar/EO/IR/RF/acoustic/Remote ID recordings, target truth, clutter/weather metadata, and handoff timestamps",
    },
}


REQUIRED_FIELDS = [
    "status",
    "readiness_score",
    "plain_need",
    "phase_i_hypothesis",
    "proposal_claim",
    "strongest_evidence",
    "primary_artifacts",
    "first_month_proof",
    "phase_i_base_demo",
    "phase_i_option_demo",
    "failure_condition",
    "do_not_overclaim",
    "external_access_request",
]


def validate_topics(topics: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    expected = {"QSPARX", "NV059", "NV061", "NV062", "NV063", "NV065", "NP002"}
    if set(topics) != expected:
        errors.append(f"topic set mismatch: {sorted(topics)}")
    for topic, packet in topics.items():
        for field in REQUIRED_FIELDS:
            value = packet.get(field)
            if value in (None, "", [], {}):
                errors.append(f"{topic} missing {field}")
        if packet.get("status") not in {"GO", "CONDITIONAL GO", "PARTNER GO"}:
            errors.append(f"{topic} has invalid status")
        score = packet.get("readiness_score")
        if not isinstance(score, int) or not 0 <= score <= 100:
            errors.append(f"{topic} readiness_score must be an integer 0-100")
        for artifact in packet.get("primary_artifacts", []):
            if not (ROOT / artifact).exists():
                errors.append(f"{topic} missing artifact {artifact}")
    return errors


def write_markdown(topics: dict[str, dict[str, Any]]) -> None:
    sections = [
        "# Topic Proposal Packets",
        "",
        "These packets are the proposal-writer view of the evidence base. They",
        "separate what can be claimed in Phase I from what still requires",
        "sponsor data, credentials, or partners.",
    ]
    for topic, packet in topics.items():
        evidence = "\n".join(
            f"- {item}" for item in packet["strongest_evidence"]
        )
        artifacts = "\n".join(
            f"- `{artifact}`" for artifact in packet["primary_artifacts"]
        )
        sections.extend(
            [
                "",
                f"## {topic} — {packet['status']} ({packet['readiness_score']}/100)",
                "",
                f"**Need:** {packet['plain_need']}",
                "",
                f"**Hypothesis:** {packet['phase_i_hypothesis']}",
                "",
                f"**Proposal claim:** {packet['proposal_claim']}",
                "",
                "**Strongest evidence:**",
                "",
                evidence,
                "",
                "**Primary artifacts:**",
                "",
                artifacts,
                "",
                f"**First-month proof:** {packet['first_month_proof']}",
                "",
                f"**Base demo:** {packet['phase_i_base_demo']}",
                "",
                f"**Option demo:** {packet['phase_i_option_demo']}",
                "",
                f"**Failure condition:** {packet['failure_condition']}",
                "",
                f"**Do not overclaim:** {packet['do_not_overclaim']}",
                "",
                f"**External access request:** {packet['external_access_request']}",
            ]
        )
    (OUTPUT / "TOPIC_PROPOSAL_PACKETS.md").write_text("\n".join(sections) + "\n")


def main() -> None:
    errors = validate_topics(TOPICS)
    if errors:
        raise SystemExit("\n".join(errors))
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "topic_readiness.json").write_text(
        json.dumps(
            {
                "format": "assureedge-topic-readiness/v1",
                "topics": TOPICS,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    write_markdown(TOPICS)
    print(f"wrote {(OUTPUT / 'topic_readiness.json').relative_to(ROOT)}")
    print(f"wrote {(OUTPUT / 'TOPIC_PROPOSAL_PACKETS.md').relative_to(ROOT)}")


if __name__ == "__main__":
    main()
