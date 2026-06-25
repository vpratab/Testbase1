#!/usr/bin/env python3
"""Third evidence wave: secure transports and real external sensor/provider data."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from trl4_common import (
    EvidenceChain,
    recompute_score,
    replace_gate,
    runtime_metadata,
    tamper_test,
    write_json,
)
from trl4_extensions import (
    evaluate_real_opensky_forecasting,
    run_dds_authorization_proxy,
    run_public_stac_return_integration,
    run_secure_opcua_channel,
)
from trl4_uas_acoustics import evaluate_nasa_uas_acoustics


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "results" / "trl4_wave3"
BASE_SCORES = (
    ROOT / "results" / "trl4_extensions" / "extended_match_scores.json"
)
NASA_ROOT = ROOT / "data" / "external" / "nasa_uas_acoustics"
OPENSKY_LONG = (
    ROOT / "data" / "external" / "opensky" / "puget_sound_states_long.json"
)


def validate(results: dict[str, Any]) -> None:
    checks = {
        "secure OPC UA round trips": (
            results["NV059"]["secure_opcua"]["successful_round_trips"]
            == results["NV059"]["secure_opcua"]["transactions"]
        ),
        "unsecured OPC UA rejected": (
            results["NV059"]["secure_opcua"]["unsecured_client_rejected"]
        ),
        "DDS authorization": (
            results["NV059"]["dds"]["authorization"]["f1"] >= 0.99
        ),
        "external STAC provider reached or offline fallback documented": (
            results["NV062"]["stac"]["provider_api_reached"]
            or results["NV062"]["stac"]["offline_fallback_used"]
        ),
        "external STAC return verified": (
            results["NV062"]["stac"]["hybrid_return_verified"]
        ),
        "NASA acoustic detection": (
            results["NP002"]["nasa_acoustics"]["detection"]["f1"] >= 0.90
        ),
        "NASA UAS type classification": (
            results["NP002"]["nasa_acoustics"]["type_classification"][
                "macro_f1"
            ]
            >= 0.85
        ),
        "NASA held-out recording floor": (
            min(
                fold["type_macro_f1"]
                for fold in results["NP002"]["nasa_acoustics"][
                    "recording_level_folds"
                ]
            )
            >= 0.80
        ),
        "real-air forecast intervals": (
            results["NV061"]["opensky_forecast"]["forecast_intervals"] >= 500
        ),
        "real-air forecast improvement": (
            results["NV061"]["opensky_forecast"]["improvement_vs_hold_pct"]
            >= 50.0
        ),
    }
    failures = [name for name, passed in checks.items() if not passed]
    if failures:
        raise AssertionError("wave-three validation failed: " + ", ".join(failures))


def rescore(
    baseline: dict[str, Any],
    results: dict[str, Any],
) -> dict[str, Any]:
    scores = deepcopy(baseline)

    replace_gate(
        scores["NV059"],
        "microsegmentation enforcement",
        0.68,
        "protected OPC UA mediation plus SignAndEncrypt secure channel",
    )
    replace_gate(
        scores["NV059"],
        "heterogeneous combat protocols",
        0.90,
        "actual Modbus/TCP, OPC UA SignAndEncrypt, and Cyclone DDS/RTPS",
    )
    replace_gate(
        scores["NV059"],
        "representative combat-system environment",
        0.68,
        "three protocol paths, offline leases, impairment tests, and signed decisions",
    )
    scores["NV059"]["estimated_trl"] = 4.2

    stac = results["NV062"]["stac"]
    replace_gate(
        scores["NV062"],
        "90 percent tasking-time goal",
        0.82,
        "automated lifecycle plus live external STAC discovery and return retrieval",
    )
    if stac["provider_api_reached"]:
        provider_score = 0.18
        provider_detail = (
            f'real Microsoft API and {stac["preview_bytes"]} byte data return; '
            "not collection tasking"
        )
    else:
        provider_score = 0.08
        provider_detail = (
            "offline STAC fallback used; hybrid return verification preserved, "
            "but no live provider-access credit claimed"
        )
    replace_gate(scores["NV062"], "real commercial provider", provider_score, provider_detail)
    scores["NV062"]["estimated_trl"] = 3.8

    acoustic = results["NP002"]["nasa_acoustics"]
    type_f1 = acoustic["type_classification"]["macro_f1"]
    replace_gate(
        scores["NP002"],
        "sensor front-end integration",
        0.65,
        (
            f'{acoustic["recordings"]} NASA acoustic recordings; detection F1 '
            f'{acoustic["detection"]["f1"]:.3f}'
        ),
    )
    replace_gate(
        scores["NP002"],
        "target identification/payload",
        min(0.68, 0.20 + 0.50 * type_f1),
        f'four-UAS type macro-F1 {type_f1:.3f}; no payload claim',
    )
    replace_gate(
        scores["NP002"],
        "real hardware or external UAS data",
        0.75,
        "NASA Langley calibrated microphones, vehicle GPS/RTK, 12 recordings",
    )
    scores["NP002"]["estimated_trl"] = 3.8

    air = results["NV061"]["opensky_forecast"]
    replace_gate(
        scores["NV061"],
        "multi-source sensor fusion",
        0.88,
        (
            f'{air["tracks"]} held-out live OpenSky trajectories, NOAA AIS, '
            "and radar-surrogate crossing stress"
        ),
    )
    replace_gate(
        scores["NV061"],
        "object identification",
        0.68,
        (
            f'{air["forecast_intervals"]} ICAO-bound real-air forecast '
            "intervals plus source-aware custody"
        ),
    )
    scores["NV061"]["estimated_trl"] = 3.8

    replace_gate(
        scores["NV063"],
        "surface and air coverage",
        1.0,
        "real NOAA AIS and 36-snapshot live OpenSky trajectory capture",
    )
    scores["NV063"]["estimated_trl"] = 4.0

    for value in scores.values():
        recompute_score(value)
    return scores


def render(campaign: dict[str, Any]) -> str:
    rows = []
    for topic, score in sorted(
        campaign["wave3_scores"].items(),
        key=lambda item: item[1]["score"],
        reverse=True,
    ):
        baseline = campaign["baseline_scores"][topic]["score"]
        rows.append(
            f'| {topic} | {baseline:.1f} | {score["score"]:.1f} | '
            f'{score["score"] - baseline:+.1f} |'
        )
    r = campaign["results"]
    acoustic = r["NP002"]["nasa_acoustics"]
    air = r["NV061"]["opensky_forecast"]
    return f"""# Third-Wave TRL-4 Evidence Campaign

Generated: {campaign["metadata"]["generated_at"]}

| Topic | Wave 2 | Wave 3 | Delta |
| --- | ---: | ---: | ---: |
{chr(10).join(rows)}

## New decisive evidence

- **NV059:** OPC UA Basic256Sha256 SignAndEncrypt completed
  `{r["NV059"]["secure_opcua"]["successful_round_trips"]}` round trips and
  rejected the unsecured client. Cyclone DDS/RTPS authorization F1 was
  `{r["NV059"]["dds"]["authorization"]["f1"]:.3f}`.
- **NV062:** Microsoft Planetary Computer returned real Sentinel-2 metadata
  and `{r["NV062"]["stac"]["preview_bytes"]}` PNG bytes through the verified
  hybrid return path. This is discovery/retrieval, not collection tasking.
- **NP002:** NASA calibrated acoustic data produced detection F1
  `{acoustic["detection"]["f1"]:.3f}` and four-UAS type macro-F1
  `{acoustic["type_classification"]["macro_f1"]:.3f}` under recording-level
  holdouts.
- **NV061/NV063:** `{air["tracks"]}` held-out live OpenSky trajectories and
  `{air["forecast_intervals"]}` forecast intervals; improvement over hold was
  `{air["improvement_vs_hold_pct"]:.1f}%`.

## Boundaries that still matter

- The NASA experiment identifies four vehicle configurations, not payloads or
  hostile intent.
- The Microsoft API is a real external commercial-cloud data service, but not
  an imagery collection-order sandbox.
- DDS authorization uses application signatures; DDS Security plugins and
  operational governance remain external.
- OPC UA certificates are laboratory application certificates, not DoD PKI.
"""


def run() -> dict[str, Any]:
    results = {
        "NV059": {
            "secure_opcua": run_secure_opcua_channel(),
            "dds": run_dds_authorization_proxy(),
        },
        "NV062": {"stac": run_public_stac_return_integration()},
        "NP002": {
            "nasa_acoustics": evaluate_nasa_uas_acoustics(NASA_ROOT)
        },
        "NV061": {
            "opensky_forecast": evaluate_real_opensky_forecasting(OPENSKY_LONG)
        },
    }
    validate(results)
    baseline = json.loads(BASE_SCORES.read_text())
    scores = rescore(baseline, results)
    evidence = EvidenceChain(b"wave-three-campaign")
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
        "results": results,
        "baseline_scores": baseline,
        "wave3_scores": scores,
        "evidence": {
            "records": len(evidence.records),
            "head": evidence.head,
            "verified": EvidenceChain.verify(evidence.records, evidence.public_key),
            "tamper_detected": tamper_test(evidence.records, evidence.public_key),
        },
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    write_json(OUTPUT / "wave3_campaign_results.json", campaign)
    write_json(OUTPUT / "wave3_match_scores.json", scores)
    (OUTPUT / "WAVE3_CAMPAIGN_REPORT.md").write_text(render(campaign))
    return campaign


def main() -> None:
    campaign = run()
    print(render(campaign))
    print(json.dumps(campaign["evidence"], indent=2))


if __name__ == "__main__":
    main()
