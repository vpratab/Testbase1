#!/usr/bin/env python3
"""Run the next locally executable TRL-4 experiments and conservatively rescore."""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
from copy import deepcopy
from pathlib import Path
from typing import Any

from prepare_opensky import collect
from trl4_common import (
    EvidenceChain,
    recompute_score,
    replace_gate,
    runtime_metadata,
    tamper_test,
    write_json,
)
from trl4_extensions import (
    evaluate_calibrated_ais_pol,
    evaluate_mixed_domain_custody,
    run_cuas_scale_and_fusion_stress,
    run_opcua_enforcement_proxy,
    run_qsparx_extension,
    run_secure_provider_workflow_extension,
    run_sensor_constraint_stress,
)
from trl4_tracks import load_real_ais_tracks


ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT = ROOT / "results" / "trl4_extensions"
BASE_SCORES = ROOT / "results" / "trl4_campaign" / "match_scores.json"
AIS_PATH = ROOT / "data" / "processed" / "noaa_ais_puget_sound_2020_02_15.csv"
OPENSKY_PATH = ROOT / "data" / "external" / "opensky" / "puget_sound_states.json"
PZDR_ROOT = Path("/Users/giansingh/Documents/GitHub/pzdr-reference")
RTVLAS_ROOT = Path(
    "/Users/giansingh/Documents/GitHub/codex-audit-pzd-rtvlas/RTVLASOPEN-main"
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
        0.72,
        (
            f'{q["active_tls_discovery"]["handshakes_succeeded"]} active TLS '
            f'endpoint plus {q["key_and_config_dependencies"]["files_scanned"]} '
            "key/config files"
        ),
    )
    replace_gate(
        scores["QSPARX"],
        "key-management and legacy interoperability",
        0.78,
        (
            f'{q["key_and_config_dependencies"]["dependency_edges"]} verified '
            "configuration-to-key dependency edges plus migration waves"
        ),
    )

    zt = results["NV059"]
    replace_gate(
        scores["NV059"],
        "microsegmentation enforcement",
        0.58,
        "protected OPC UA data node rejects direct writes; policy proxy mediates changes",
    )
    replace_gate(
        scores["NV059"],
        "heterogeneous combat protocols",
        0.65,
        "actual Modbus/TCP parser plus actual OPC UA client/server path",
    )
    replace_gate(
        scores["NV059"],
        "representative combat-system environment",
        0.55,
        (
            f'{zt["requests"]} OPC UA transactions across connected, delayed, '
            "lossy, and partitioned conditions"
        ),
    )

    st = results["NV062"]
    replace_gate(
        scores["NV062"],
        "90 percent tasking-time goal",
        0.78,
        (
            f'{st["tasks"]} automated lifecycle transactions, cancellations, '
            "idempotency, and return manifests"
        ),
    )
    replace_gate(
        scores["NV062"],
        "IL-5/IL-6 architecture",
        0.45,
        "purpose-bound gateway and integrity manifests modeled; no accreditation",
    )

    cuas = results["NP002"]
    replace_gate(
        scores["NP002"],
        "scalability evidence",
        0.95,
        (
            f'{cuas["maximum_uas"]} UAS stress; '
            f'{cuas["scale"]["150"]["p95_update_ms"]:.2f} ms p95 association'
        ),
    )
    replace_gate(
        scores["NP002"],
        "sensor front-end integration",
        0.48,
        "EO/RF/acoustic fusion interface tested with synthetic channel scores",
    )

    mixed = results["NV061"]
    replace_gate(
        scores["NV061"],
        "multi-source sensor fusion",
        0.78,
        (
            f'{mixed["air_tracks"]} OpenSky air plus {mixed["surface_tracks"]} '
            "NOAA AIS surface tracks and radar-surrogate observations"
        ),
    )
    replace_gate(
        scores["NV061"],
        "object identification",
        0.55,
        (
            f'source-aware custody accuracy {mixed["source_aware_accuracy"]:.3f}; '
            f'{mixed["source_aware_identity_switches"]} identity switches'
        ),
    )

    pol = results["NV063"]
    robust = pol["robustness"]
    replace_gate(
        scores["NV063"],
        "anomaly accuracy",
        robust["f1_mean"],
        f'cross-seed persistent-alert F1 {robust["f1_mean"]:.3f}',
    )
    replace_gate(
        scores["NV063"],
        "anomaly recall",
        robust["recall_mean"],
        f'cross-seed recall {robust["recall_mean"]:.3f}',
    )
    replace_gate(
        scores["NV063"],
        "false-alert control",
        max(0.0, 1.0 - robust["false_positive_rate_mean"] / 0.25),
        f'cross-seed FPR {robust["false_positive_rate_mean"]:.3f}',
    )
    replace_gate(
        scores["NV063"],
        "surface and air coverage",
        0.90,
        "real NOAA AIS and live-captured OpenSky air-state ingestion",
    )
    replace_gate(
        scores["NV063"],
        "notional radar/composite tracks",
        0.70,
        "mixed-domain crossing stress with cooperative dropout and radar noise",
    )

    sensor = results["NV065"]
    replace_gate(
        scores["NV065"],
        "program-of-record radar realism",
        0.50,
        "four named surrogates now enforce time, power, and illumination constraints",
    )
    replace_gate(
        scores["NV065"],
        "SSDS integration constraints",
        0.55,
        (
            f'{sensor["constrained_invalid_sensor_schedules"]} invalid schedules '
            "after constraint enforcement"
        ),
    )
    for value in scores.values():
        recompute_score(value)
    return scores


def _robust_pol(tracks: list[Any]) -> dict[str, Any]:
    runs = [
        evaluate_calibrated_ais_pol(tracks, seed)
        for seed in (10, 11, 12, 13, 14, 63)
    ]
    return {
        "seeds": [10, 11, 12, 13, 14, 63],
        "f1_mean": statistics.fmean(run["f1"] for run in runs),
        "f1_minimum": min(run["f1"] for run in runs),
        "recall_mean": statistics.fmean(run["recall"] for run in runs),
        "recall_minimum": min(run["recall"] for run in runs),
        "false_positive_rate_mean": statistics.fmean(
            run["false_positive_rate"] for run in runs
        ),
        "false_positive_rate_maximum": max(
            run["false_positive_rate"] for run in runs
        ),
        "runs": runs,
    }


def validate_results(results: dict[str, Any]) -> None:
    checks = {
        "QSPARX active TLS discovery": (
            results["QSPARX"]["active_tls_discovery"]["handshakes_succeeded"] == 1
        ),
        "QSPARX dependency evidence": (
            results["QSPARX"]["key_and_config_dependencies"]["dependency_edges"] >= 2
        ),
        "NV059 direct-write protection": (
            results["NV059"]["direct_protected_write_blocked"]
        ),
        "NV059 authorization F1": (
            results["NV059"]["authorization"]["f1"] >= 0.98
        ),
        "NV062 replay rejection": (
            results["NV062"]["duplicate_blocked"] == results["NV062"]["tasks"]
        ),
        "NV062 return tamper rejection": (
            results["NV062"]["tampered_return_blocked"]
            == results["NV062"]["return_integrity_verified"]
        ),
        "NP002 150-UAS scale": results["NP002"]["maximum_uas"] >= 150,
        "NP002 150-UAS latency": (
            results["NP002"]["scale"]["150"]["p95_update_ms"] < 100.0
        ),
        "NV061 source-aware custody improvement": (
            results["NV061"]["source_aware_accuracy"]
            > results["NV061"]["position_only_accuracy"]
        ),
        "NV061 identity-switch improvement": (
            results["NV061"]["source_aware_identity_switches"]
            < results["NV061"]["position_only_identity_switches"]
        ),
        "NV063 robust false-alert control": (
            results["NV063"]["robustness"]["false_positive_rate_mean"] <= 0.12
        ),
        "NV063 robust recall": (
            results["NV063"]["robustness"]["recall_mean"] >= 0.74
        ),
        "NV065 constraint correctness": (
            results["NV065"]["constrained_invalid_sensor_schedules"] == 0
        ),
    }
    failures = [name for name, passed in checks.items() if not passed]
    if failures:
        raise AssertionError(
            "extended campaign validation failed: " + ", ".join(failures)
        )


def render_report(campaign: dict[str, Any]) -> str:
    rows = []
    for topic, score in sorted(
        campaign["extended_scores"].items(),
        key=lambda item: item[1]["score"],
        reverse=True,
    ):
        baseline = campaign["baseline_scores"][topic]["score"]
        rows.append(
            f'| {topic} | {baseline:.1f} | {score["score"]:.1f} | '
            f'{score["score"] - baseline:+.1f} |'
        )
    r = campaign["results"]
    return f"""# Extended TRL-4 Evidence Campaign

Generated: {campaign["metadata"]["generated_at"]}

These score movements only credit newly measured evidence. They still do not
claim access to AFDW, SSDS, accredited IL-5/IL-6 infrastructure, commercial
provider production APIs, or program-of-record sensor parameters.

| Topic | Previous | Extended | Delta |
| --- | ---: | ---: | ---: |
{chr(10).join(rows)}

## New measured evidence

- **QSPARX:** active TLS handshake and certificate inspection plus
  `{r["QSPARX"]["key_and_config_dependencies"]["files_scanned"]}` key/config
  files and dependency edges.
- **NV059:** actual OPC UA server/client mediation over
  `{r["NV059"]["requests"]}` requests; direct protected writes were blocked;
  authorization F1 `{r["NV059"]["authorization"]["f1"]:.3f}`.
- **NV062:** `{r["NV062"]["tasks"]}` lifecycle transactions with replay,
  cancellation, chunk-manifest integrity, and tampered-return rejection.
- **NP002:** association stress through `{r["NP002"]["maximum_uas"]}` UAS;
  synthetic three-channel fusion F1
  `{r["NP002"]["synthetic_front_end_fusion"]["f1"]:.3f}`.
- **NV061:** `{r["NV061"]["air_tracks"]}` live-captured OpenSky tracks plus
  `{r["NV061"]["surface_tracks"]}` NOAA AIS tracks; source-aware crossing
  accuracy `{r["NV061"]["source_aware_accuracy"]:.3f}` with
  `{r["NV061"]["source_aware_identity_switches"]}` switches.
- **NV063:** persistence calibration reduced cross-seed mean FPR to
  `{r["NV063"]["robustness"]["false_positive_rate_mean"]:.3f}` at mean recall
  `{r["NV063"]["robustness"]["recall_mean"]:.3f}`.
- **NV065:** constraint scheduler reduced invalid sensor schedules from
  `{r["NV065"]["naive_invalid_sensor_schedules"]}` to
  `{r["NV065"]["constrained_invalid_sensor_schedules"]}`.

## Remaining decisive external proofs

- QSPARX: enterprise CMDB/range and AFDW-representative endpoint population.
- NV059: actual network fabric microsegmentation, CAC middleware, and DDS.
- NV062: a commercial-provider sandbox and accreditation evidence.
- NP002: public or government EO/RF/acoustic sensor data and target-type labels.
- NV061/NV063: longer air trajectories and an operational composite-track feed.
- NV065: traceable program-of-record sensor models and SSDS tasking interface.
"""


def run(output: Path) -> dict[str, Any]:
    if not OPENSKY_PATH.exists():
        collect(OPENSKY_PATH)
    tracks = load_real_ais_tracks(AIS_PATH, maximum_tracks=500)
    pol = evaluate_calibrated_ais_pol(tracks)
    pol["robustness"] = _robust_pol(tracks)
    results = {
        "QSPARX": run_qsparx_extension([PZDR_ROOT, RTVLAS_ROOT]),
        "NV059": run_opcua_enforcement_proxy(),
        "NV062": run_secure_provider_workflow_extension(),
        "NP002": run_cuas_scale_and_fusion_stress(),
        "NV061": evaluate_mixed_domain_custody(tracks, OPENSKY_PATH),
        "NV063": pol,
        "NV065": run_sensor_constraint_stress(),
    }
    validate_results(results)
    baseline = json.loads(BASE_SCORES.read_text())
    extended = rescore(baseline, results)
    evidence = EvidenceChain(b"extended-trl4-campaign")
    for topic, result in results.items():
        evidence.append(
            topic,
            {
                "result_sha256": hashlib.sha256(
                    json.dumps(result, sort_keys=True).encode()
                ).hexdigest(),
                "score": extended[topic]["score"],
            },
        )
    campaign = {
        "metadata": runtime_metadata(),
        "data": {
            "opensky_path": str(OPENSKY_PATH),
            "opensky_sha256": hashlib.sha256(OPENSKY_PATH.read_bytes()).hexdigest(),
            "ais_path": str(AIS_PATH),
        },
        "results": results,
        "baseline_scores": baseline,
        "extended_scores": extended,
        "evidence": {
            "records": len(evidence.records),
            "head": evidence.head,
            "verified": EvidenceChain.verify(evidence.records, evidence.public_key),
            "tamper_detected": tamper_test(evidence.records, evidence.public_key),
        },
    }
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "extended_campaign_results.json", campaign)
    write_json(output / "extended_match_scores.json", extended)
    for topic, result in results.items():
        write_json(output / "topics" / f"{topic.lower()}_extension.json", result)
    (output / "EXTENDED_CAMPAIGN_REPORT.md").write_text(render_report(campaign))
    return campaign


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    campaign = run(args.output)
    print(render_report(campaign))
    print(json.dumps(campaign["evidence"], indent=2))


if __name__ == "__main__":
    main()
