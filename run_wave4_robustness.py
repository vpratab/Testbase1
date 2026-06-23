#!/usr/bin/env python3
"""Repeat fourth-wave numerical and enforcement experiments across seeds."""

from __future__ import annotations

import json
import statistics
from pathlib import Path

from run_wave4_campaign import NASA_ROOT, OPENSKY_LONG
from trl4_common import write_json
from trl4_wave4 import (
    evaluate_opensky_air_anomalies,
    run_composite_track_interface,
    run_cross_domain_gateway_controls,
    run_cross_domain_priority_ranking,
    run_enterprise_crypto_range,
    run_network_microsegmentation_gateway,
    run_traceable_radar_scheduler,
    run_uas_typed_track_fusion,
)


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "results" / "trl4_wave4"


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "minimum": min(values),
        "mean": statistics.fmean(values),
        "maximum": max(values),
    }


def run() -> dict:
    radar_runs = [
        run_traceable_radar_scheduler(seed=6504 + seed)
        for seed in range(5)
    ]
    air_runs = [
        evaluate_opensky_air_anomalies(OPENSKY_LONG, seed=6305 + seed)
        for seed in range(5)
    ]
    priority_runs = [
        run_cross_domain_priority_ranking(OPENSKY_LONG, seed=6104 + seed)
        for seed in range(5)
    ]
    typed_runs = [
        run_uas_typed_track_fusion(NASA_ROOT, seed=2004 + seed)
        for seed in range(5)
    ]
    range_result = run_enterprise_crypto_range(16)
    micro = run_network_microsegmentation_gateway(40, 20)
    controls = run_cross_domain_gateway_controls(transactions=240)
    interface = run_composite_track_interface(5000)
    return {
        "QSPARX": {
            "inventory_accuracy": range_result["endpoint_inventory_accuracy"],
            "active_endpoints": range_result["active_tls_endpoints"],
            "dependency_edges": range_result["dependency_edges"],
        },
        "NV059": {
            "authorized_rate": micro["authorized_completed"]
            / micro["authorized_requests"],
            "unauthorized_deny_rate": micro["unauthorized_denied"]
            / micro["unauthorized_requests"],
            "p95_us": micro["p95_us"],
        },
        "NV061": {
            "priority_recall": summarize(
                [
                    value["priority_recall_at_threat_count"]
                    for value in priority_runs
                ]
            )
        },
        "NV062": {
            "control_f1": controls["authorization"]["f1"],
            "evidence_verified": controls["evidence"]["verified"],
        },
        "NP002": {
            "typed_accuracy": summarize(
                [value["acoustic_typed_accuracy"] for value in typed_runs]
            ),
            "typed_identity_switches": summarize(
                [
                    float(value["acoustic_typed_identity_switches"])
                    for value in typed_runs
                ]
            ),
        },
        "NV063": {
            "air_f1": summarize([value["f1"] for value in air_runs]),
            "air_fpr": summarize(
                [value["false_positive_rate"] for value in air_runs]
            ),
            "interface_tamper_rate": interface["tamper_rejected"]
            / interface["tamper_cases"],
        },
        "NV065": {
            "invalid_schedules": summarize(
                [float(value["invalid_schedules"]) for value in radar_runs]
            ),
            "scheduler_p95_us": summarize(
                [value["scheduler_p95_us"] for value in radar_runs]
            ),
            "double_power_db": summarize(
                [
                    value["radar_equation_validation"]["double_power_db"]
                    for value in radar_runs
                ]
            ),
        },
    }


def render(result: dict) -> str:
    return f"""# Fourth-Wave Robustness

| Topic | Robustness floor |
| --- | --- |
| QSPARX | endpoint inventory {result["QSPARX"]["inventory_accuracy"]:.3f}; {result["QSPARX"]["active_endpoints"]} active endpoints; {result["QSPARX"]["dependency_edges"]} dependency edges |
| NV059 | authorization {result["NV059"]["authorized_rate"]:.3f}; unauthorized denial {result["NV059"]["unauthorized_deny_rate"]:.3f}; p95 {result["NV059"]["p95_us"]:.1f} us |
| NV061 | priority recall minimum {result["NV061"]["priority_recall"]["minimum"]:.3f} |
| NV062 | cross-domain control F1 {result["NV062"]["control_f1"]:.3f}; evidence verified {result["NV062"]["evidence_verified"]} |
| NP002 | typed association minimum {result["NP002"]["typed_accuracy"]["minimum"]:.3f}; identity-switch maximum {result["NP002"]["typed_identity_switches"]["maximum"]:.0f} |
| NV063 | air F1 minimum {result["NV063"]["air_f1"]["minimum"]:.3f}; FPR maximum {result["NV063"]["air_fpr"]["maximum"]:.3f}; tamper rejection {result["NV063"]["interface_tamper_rate"]:.3f} |
| NV065 | invalid schedules maximum {result["NV065"]["invalid_schedules"]["maximum"]:.0f}; scheduler p95 maximum {result["NV065"]["scheduler_p95_us"]["maximum"]:.1f} us |
"""


def main() -> None:
    result = run()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    write_json(OUTPUT / "wave4_robustness.json", result)
    (OUTPUT / "WAVE4_ROBUSTNESS.md").write_text(render(result))
    print(render(result))
    print(json.dumps({"output": str(OUTPUT)}, indent=2))


if __name__ == "__main__":
    main()
