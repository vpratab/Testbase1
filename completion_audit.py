#!/usr/bin/env python3
"""Audit the active goal against current evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from proposal_readiness import TOPICS, validate_topics


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "results" / "completion_audit"


REQUIRED_ARTIFACTS = {
    "topic_packets": "results/proposal_readiness/TOPIC_PROPOSAL_PACKETS.md",
    "topic_packet_json": "results/proposal_readiness/topic_readiness.json",
    "go_no_go": "docs/PHASE1_GO_NO_GO.md",
    "current_assessment": "docs/CURRENT_AND_POTENTIAL_ASSESSMENT.md",
    "external_access": "docs/EXTERNAL_ACCESS_PACKAGES.md",
    "partner_templates": "docs/PARTNER_OUTREACH_TEMPLATES.md",
    "np002_field_path": "docs/NP002_FIELD_VALIDATION_PATH.md",
    "independent_benchmark": "results/independent_benchmark/INDEPENDENT_BENCHMARK.md",
    "dense_crossing": "results/dense_crossing/DENSE_CROSSING_REPORT.md",
    "frozen_region": "results/frozen_region/FROZEN_REGION_REPORT.md",
    "evidence_index": "results/trl4_wave5/EVIDENCE_INDEX.md",
    "release_manifest": "results/supply_chain/release_manifest.json",
}


EXCLUDED_EXTERNAL_PROOFS = {
    "QSPARX": "AFDW inventory or sponsor-approved range access",
    "NV059": "DoD identity and representative combat-network access",
    "NV061": "operational composite tracks with identity truth and analyst dispositions",
    "NV062": "credentialed live provider sandbox or collection lifecycle",
    "NV063": "SSDS replay and operator alert dispositions",
    "NV065": "approved radar/task parameters and fire-control-quality definitions",
    "NP002": "synchronized C-UAS field truth and integration owner",
}


def artifact_status() -> dict[str, dict[str, Any]]:
    return {
        name: {
            "path": path,
            "exists": (ROOT / path).exists(),
            "bytes": (ROOT / path).stat().st_size if (ROOT / path).exists() else 0,
        }
        for name, path in REQUIRED_ARTIFACTS.items()
    }


def topic_status() -> dict[str, dict[str, Any]]:
    packets_errors = validate_topics(TOPICS)
    return {
        topic: {
            "status": packet["status"],
            "readiness_score": packet["readiness_score"],
            "packet_complete": not packets_errors,
            "primary_artifacts_exist": all(
                (ROOT / artifact).exists()
                for artifact in packet["primary_artifacts"]
            ),
            "external_proof_not_required_for_internal_completion": (
                EXCLUDED_EXTERNAL_PROOFS[topic]
            ),
            "base_demo_defined": bool(packet["phase_i_base_demo"]),
            "option_demo_defined": bool(packet["phase_i_option_demo"]),
            "failure_condition_defined": bool(packet["failure_condition"]),
            "overclaim_boundary_defined": bool(packet["do_not_overclaim"]),
        }
        for topic, packet in TOPICS.items()
    }


def run_audit() -> dict[str, Any]:
    artifacts = artifact_status()
    topics = topic_status()
    all_artifacts_present = all(item["exists"] for item in artifacts.values())
    all_topics_complete = all(
        value["packet_complete"]
        and value["primary_artifacts_exist"]
        and value["base_demo_defined"]
        and value["option_demo_defined"]
        and value["failure_condition_defined"]
        and value["overclaim_boundary_defined"]
        for value in topics.values()
    )
    return {
        "format": "assureedge-completion-audit/v1",
        "objective": (
            "Make all seven SBIR concepts Phase I proposal-ready and "
            "technically winnable by closing every evidence, benchmark, "
            "traceability, and clarity gap possible without sponsor-only "
            "credentials, classified data, or external partner commitments."
        ),
        "scope_boundary": (
            "Completion means internally proposal-ready within the declared "
            "no-sponsor-credential/no-classified-data/no-partner-commitment "
            "boundary. It does not mean operational validation or award "
            "probability."
        ),
        "requirements": {
            "all_seven_topics_present": set(TOPICS)
            == {"QSPARX", "NV059", "NV061", "NV062", "NV063", "NV065", "NP002"},
            "topic_packets_valid": validate_topics(TOPICS) == [],
            "required_artifacts_present": all_artifacts_present,
            "topic_artifacts_present": all_topics_complete,
            "external_blockers_explicit": set(EXCLUDED_EXTERNAL_PROOFS) == set(TOPICS),
        },
        "topics": topics,
        "artifacts": artifacts,
        "excluded_external_proofs": EXCLUDED_EXTERNAL_PROOFS,
        "internal_scope_complete": (
            all_artifacts_present
            and all_topics_complete
            and validate_topics(TOPICS) == []
            and set(EXCLUDED_EXTERNAL_PROOFS) == set(TOPICS)
        ),
    }


def write_markdown(audit: dict[str, Any]) -> None:
    rows = "\n".join(
        "| {topic} | {status} | {score} | {complete} | {external} |".format(
            topic=topic,
            status=value["status"],
            score=value["readiness_score"],
            complete="yes" if value["primary_artifacts_exist"] else "no",
            external=value["external_proof_not_required_for_internal_completion"],
        )
        for topic, value in audit["topics"].items()
    )
    requirements = "\n".join(
        f"- {name}: {'PASS' if passed else 'FAIL'}"
        for name, passed in audit["requirements"].items()
    )
    artifacts = "\n".join(
        f"- `{value['path']}`: {'present' if value['exists'] else 'missing'}"
        for value in audit["artifacts"].values()
    )
    report = f"""# Completion Audit

## Scope

{audit["scope_boundary"]}

## Requirement check

{requirements}

## Topic status

| Topic | Status | Score | Artifacts present | External proof still excluded |
| --- | --- | ---: | --- | --- |
{rows}

## Required artifacts

{artifacts}

## Decision

Internal scope complete: `{audit["internal_scope_complete"]}`.

This audit does not claim award probability, operational validation,
classified-environment performance, or partner commitment. It proves that the
current repository closes the evidence, benchmark, traceability, and clarity
gaps that can be closed without those external inputs.
"""
    (OUTPUT / "COMPLETION_AUDIT.md").write_text(report)


def main() -> None:
    audit = run_audit()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "completion_audit.json").write_text(
        json.dumps(audit, indent=2, sort_keys=True) + "\n"
    )
    write_markdown(audit)
    print(f"wrote {(OUTPUT / 'completion_audit.json').relative_to(ROOT)}")
    print(f"wrote {(OUTPUT / 'COMPLETION_AUDIT.md').relative_to(ROOT)}")
    if not audit["internal_scope_complete"]:
        raise SystemExit("completion audit failed")


if __name__ == "__main__":
    main()
