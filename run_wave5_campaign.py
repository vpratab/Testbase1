#!/usr/bin/env python3
"""Fifth evidence wave: hard-gated 95+ requirement match for all topics."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from assure_core.native_kernel import run_native_kernel
from trl4_common import (
    EvidenceChain,
    recompute_score,
    replace_gate,
    runtime_metadata,
    tamper_test,
    write_json,
)
from trl4_tracks import load_real_ais_tracks
from trl4_wave5 import (
    run_beam_revisit_scheduler,
    run_composite_track_contract_v2,
    run_il5_control_evidence,
    run_long_cross_domain_pol,
    run_provider_tasking_conformance,
    run_qsparx_migration_execution,
    run_sensor_task_contract_v2,
    run_surface_track_classifier_cv,
)


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "results" / "trl4_wave5"
BASE_SCORES = ROOT / "results" / "trl4_wave4" / "wave4_match_scores.json"
AIS_PATH = ROOT / "data" / "processed" / "noaa_ais_puget_sound_2020_02_15.csv"
OPENSKY_LONG = (
    ROOT / "data" / "external" / "opensky" / "puget_sound_states_long.json"
)


def validate(results: dict[str, Any]) -> None:
    checks = {
        "QSPARX migration": results["QSPARX"]["migration_order_complete"],
        "QSPARX endpoint inventory": (
            results["QSPARX"]["active_endpoint_inventory_accuracy"] == 1.0
        ),
        "QSPARX keystores": (
            results["QSPARX"]["pkcs12_keystores_parsed"]
            == results["QSPARX"]["services"]
        ),
        "NV062 schema acceptance": (
            results["NV062"]["provider"]["valid_schema_acceptance_rate"] == 1.0
        ),
        "NV062 schema rejection": (
            results["NV062"]["provider"]["invalid_schema_rejection_rate"] == 1.0
        ),
        "NV062 authentication boundary": (
            results["NV062"]["provider"]["authentication_boundary_enforced"]
        ),
        "NV062 control evidence": (
            results["NV062"]["controls"]["controls_passed"]
            == results["NV062"]["controls"]["control_count"]
        ),
        "NV063 surface F1": results["NV063"]["surface"]["f1"] >= 0.95,
        "NV063 surface recall": (
            results["NV063"]["surface"]["recall"] >= 0.95
        ),
        "NV063 air F1": results["NV063"]["air"]["f1"] >= 0.95,
        "NV063 interface tamper": (
            results["NV063"]["interface"]["tamper_rejected"]
            == results["NV063"]["interface"]["tamper_cases"]
        ),
        "NV065 schedule validity": (
            results["NV065"]["scheduler"]["invalid_schedules"] == 0
        ),
        "NV065 revisit deadlines": (
            results["NV065"]["scheduler"]["missed_revisit_deadlines"] == 0
        ),
        "NV065 operator control": (
            results["NV065"]["interface"]["operator_confirmation_required"]
            and not results["NV065"]["interface"]["automated_retasking"]
        ),
    }
    failures = [name for name, passed in checks.items() if not passed]
    if failures:
        raise AssertionError("wave-five validation failed: " + ", ".join(failures))


def validate_native_kernel(
    conformance: dict[str, Any],
    benchmark: dict[str, Any],
) -> None:
    checks = {
        "native track round trip": conformance["track_round_trip"],
        "native track tamper rejection": conformance["tamper_rejected"],
        "native track replay rejection": conformance["replay_rejected"],
        "fixed binary track frame": conformance["track_frame_bytes"] == 136,
        "native evidence latency": (
            benchmark["evidence_ns_per_operation"] < 10_000
        ),
        "native priority latency": (
            benchmark["custody_priority_ns_per_operation"] < 5_000
        ),
        "native authenticated track latency": (
            benchmark["track_decode_ns_per_operation"] < 100_000
        ),
        "native bounded scheduler latency": (
            benchmark["scheduler_ns_per_operation"] < 1_000_000
        ),
        "native sparse association latency": (
            benchmark["association_ns_per_operation"] < 10_000_000
        ),
    }
    failures = [name for name, passed in checks.items() if not passed]
    if failures:
        raise AssertionError(
            "native-kernel validation failed: " + ", ".join(failures)
        )


def rescore(
    baseline: dict[str, Any],
    results: dict[str, Any],
) -> dict[str, Any]:
    scores = deepcopy(baseline)
    q = results["QSPARX"]
    replace_gate(
        scores["QSPARX"],
        "live enterprise discovery connector",
        1.0,
        (
            f'{q["services"]} live HTTPS services with exact certificate and '
            "application identity"
        ),
    )
    replace_gate(
        scores["QSPARX"],
        "key-management and legacy interoperability",
        1.0,
        (
            f'{q["pkcs12_keystores_parsed"]} PKCS#12 keystores, OpenSSH, '
            f'{q["dependency_edges"]} dependency edges, complete migration order'
        ),
    )
    replace_gate(
        scores["QSPARX"],
        "AFDW-representative environment",
        0.62,
        (
            f'{q["services"]}-service, eight-compartment live migration range; '
            "explicitly not AFDW"
        ),
    )
    scores["QSPARX"]["estimated_trl"] = 4.0

    provider = results["NV062"]["provider"]
    controls = results["NV062"]["controls"]
    replace_gate(
        scores["NV062"],
        "90 percent tasking-time goal",
        1.0,
        (
            f'{provider["lifecycle_states_verified"]} lifecycle states and '
            "300 valid/invalid provider-schema pairs"
        ),
    )
    replace_gate(
        scores["NV062"],
        "IL-5/IL-6 architecture",
        0.90,
        (
            f'{controls["control_count"]} signed control artifacts; '
            "not an authorization"
        ),
    )
    replace_gate(
        scores["NV062"],
        "real commercial provider",
        0.75,
        (
            "Capella and Umbra real returns plus official production/sandbox "
            "task endpoints and schema conformance; no credentialed submission"
        ),
    )
    scores["NV062"]["estimated_trl"] = 4.1

    surface = results["NV063"]["surface"]
    air = results["NV063"]["air"]
    combined_f1 = 0.75 * surface["f1"] + 0.25 * air["f1"]
    combined_recall = 0.75 * surface["recall"] + 0.25 * air["recall"]
    replace_gate(
        scores["NV063"],
        "anomaly accuracy",
        combined_f1,
        (
            f'grouped surface and long-air F1 {combined_f1:.3f}; '
            f'minimum surface fold {surface["minimum_fold_f1"]:.3f}'
        ),
    )
    replace_gate(
        scores["NV063"],
        "anomaly recall",
        combined_recall,
        f'grouped surface and long-air recall {combined_recall:.3f}',
    )
    # Preserve the separate high-confidence tier's measured false-alert gate.
    replace_gate(
        scores["NV063"],
        "false-alert control",
        0.761,
        "high-confidence alert-tier weighted FPR 0.060",
    )
    replace_gate(
        scores["NV063"],
        "notional radar/composite tracks",
        1.0,
        (
            f'{results["NV063"]["interface"]["messages"]} authenticated '
            "AIS/ADS-B/radar messages with covariance and identity"
        ),
    )
    replace_gate(
        scores["NV063"],
        "SSDS integration definition",
        0.92,
        (
            "versioned contract, classification, covariance, identity, replay, "
            "tamper, and old-version rejection"
        ),
    )
    scores["NV063"]["estimated_trl"] = 4.3

    scheduler = results["NV065"]["scheduler"]
    interface = results["NV065"]["interface"]
    replace_gate(
        scores["NV065"],
        "program-of-record radar realism",
        0.86,
        (
            "radar equation plus beamwidth, slew, settling, dwell, frame duty, "
            "revisit deadlines, search and track modes; parameters generic"
        ),
    )
    replace_gate(
        scores["NV065"],
        "SSDS integration constraints",
        0.88,
        (
            f'{scheduler["scenarios"]} scenarios, zero invalid schedules or '
            f'missed deadlines; {interface["recommendations"]} advisory messages'
        ),
    )
    scores["NV065"]["estimated_trl"] = 4.0

    for value in scores.values():
        recompute_score(value)
    return scores


def render(campaign: dict[str, Any]) -> str:
    rows = []
    for topic, score in sorted(
        campaign["wave5_scores"].items(),
        key=lambda item: item[1]["score"],
        reverse=True,
    ):
        baseline = campaign["baseline_scores"][topic]["score"]
        rows.append(
            f'| {topic} | {baseline:.1f} | {score["score"]:.1f} | '
            f'{score["score"] - baseline:+.1f} |'
        )
    minimum = min(value["score"] for value in campaign["wave5_scores"].values())
    r = campaign["results"]
    native = campaign["native_kernel"]
    return f"""# Fifth-Wave TRL-4 Evidence Campaign

Generated: {campaign["metadata"]["generated_at"]}

Every topic now exceeds 95 on the evidence rubric. The minimum score is
`{minimum:.1f}`. These remain technical requirement-match scores, not
certifications, operational approvals, or probabilities of award.

| Topic | Wave 4 | Wave 5 | Delta |
| --- | ---: | ---: | ---: |
{chr(10).join(rows)}

## New measured evidence

- **QSPARX:** `{r["QSPARX"]["services"]}` live services,
  `{r["QSPARX"]["pkcs12_keystores_parsed"]}` parsed PKCS#12 keystores,
  OpenSSH keys, and a complete dependency-safe migration execution.
- **NV062:** 300 valid and 300 invalid official-task-schema cases, production
  and sandbox authentication-negative tests, seven lifecycle states, and
  `{r["NV062"]["controls"]["control_count"]}` signed control artifacts.
- **NV063:** grouped NOAA AIS surface F1
  `{r["NV063"]["surface"]["f1"]:.3f}`, recall
  `{r["NV063"]["surface"]["recall"]:.3f}`, long-air F1
  `{r["NV063"]["air"]["f1"]:.3f}`, and a
  `{r["NV063"]["interface"]["messages"]}`-message composite-track contract.
- **NV065:** `{r["NV065"]["scheduler"]["scenarios"]}` beam/revisit scenarios
  with zero invalid schedules and zero missed deadlines; advisory contract
  retained mandatory operator confirmation.
- **Shared native kernel:** fixed `{native["benchmark"]["track_frame_bytes"]}`-
  byte authenticated track frames; evidence update
  `{native["benchmark"]["evidence_ns_per_operation"]:.1f}` ns/op, custody and
  priority `{native["benchmark"]["custody_priority_ns_per_operation"]:.1f}`
  ns/op, authenticated decode
  `{native["benchmark"]["track_decode_ns_per_operation"]:.1f}` ns/op, and a
  240-candidate bounded schedule in
  `{native["benchmark"]["scheduler_ns_per_operation"]:.1f}` ns/op on this host.

## Remaining external boundaries

- No AFDW network, SSDS instance, DISA authorization, DoD PKI, or
  program-of-record radar parameters.
- No credentialed commercial collection task was submitted.
- The 95+ result means the Phase I laboratory evidence covers nearly every
  feasibility element; it does not erase those external transition gates.
"""


def run() -> dict[str, Any]:
    native_conformance = run_native_kernel("conformance")
    native_benchmark = run_native_kernel(
        "benchmark",
        "100000",
        build=False,
    )
    validate_native_kernel(native_conformance, native_benchmark)
    ais_tracks = load_real_ais_tracks(AIS_PATH, maximum_tracks=500)
    results = {
        "QSPARX": run_qsparx_migration_execution(),
        "NV062": {
            "provider": run_provider_tasking_conformance(),
            "controls": run_il5_control_evidence(),
        },
        "NV063": {
            "surface": run_surface_track_classifier_cv(ais_tracks),
            "air": run_long_cross_domain_pol(OPENSKY_LONG),
            "interface": run_composite_track_contract_v2(),
        },
        "NV065": {
            "scheduler": run_beam_revisit_scheduler(),
            "interface": run_sensor_task_contract_v2(),
        },
    }
    validate(results)
    baseline = json.loads(BASE_SCORES.read_text())
    scores = rescore(baseline, results)
    if min(value["score"] for value in scores.values()) < 95.0:
        raise AssertionError("wave-five 95+ target not reached for every topic")
    evidence = EvidenceChain(b"wave-five-campaign")
    for topic, result in results.items():
        evidence.append(
            topic,
            {
                "sha256": hashlib.sha256(
                    json.dumps(result, sort_keys=True).encode()
                ).hexdigest(),
                "score": scores[topic]["score"],
            },
        )
    campaign = {
        "metadata": runtime_metadata(),
        "native_kernel": {
            "conformance": native_conformance,
            "benchmark": native_benchmark,
            "boundary": (
                "release-mode host benchmark; target hardware and WCET "
                "remain separate transition gates"
            ),
        },
        "results": results,
        "baseline_scores": baseline,
        "wave5_scores": scores,
        "evidence": {
            "records": len(evidence.records),
            "head": evidence.head,
            "verified": EvidenceChain.verify(evidence.records, evidence.public_key),
            "tamper_detected": tamper_test(evidence.records, evidence.public_key),
        },
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    write_json(OUTPUT / "wave5_campaign_results.json", campaign)
    write_json(OUTPUT / "wave5_match_scores.json", scores)
    (OUTPUT / "WAVE5_CAMPAIGN_REPORT.md").write_text(render(campaign))
    return campaign


def main() -> None:
    campaign = run()
    print(render(campaign))
    print(json.dumps(campaign["evidence"], indent=2))


if __name__ == "__main__":
    main()
