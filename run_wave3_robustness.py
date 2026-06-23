#!/usr/bin/env python3
"""Repeat the third-wave transport tests and summarize external-data floors."""

from __future__ import annotations

import json
import statistics
from pathlib import Path

from run_wave3_campaign import NASA_ROOT, OPENSKY_LONG
from trl4_common import write_json
from trl4_extensions import (
    evaluate_real_opensky_forecasting,
    run_dds_authorization_proxy,
    run_secure_opcua_channel,
)
from trl4_uas_acoustics import evaluate_nasa_uas_acoustics


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "results" / "trl4_wave3"


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "minimum": min(values),
        "mean": statistics.fmean(values),
        "maximum": max(values),
    }


def run() -> dict:
    secure_runs = [
        run_secure_opcua_channel(seed=5902 + seed, transactions=20)
        for seed in range(3)
    ]
    dds_runs = [
        run_dds_authorization_proxy(seed=5903 + seed, requests=60)
        for seed in range(5)
    ]
    acoustic = evaluate_nasa_uas_acoustics(NASA_ROOT)
    opensky = evaluate_real_opensky_forecasting(OPENSKY_LONG)
    result = {
        "NV059": {
            "secure_opcua_success_rate": summarize(
                [
                    run["successful_round_trips"] / run["transactions"]
                    for run in secure_runs
                ]
            ),
            "secure_opcua_p95_us": summarize(
                [run["performance"]["p95_us"] for run in secure_runs]
            ),
            "unsecured_rejection_rate": statistics.fmean(
                float(run["unsecured_client_rejected"])
                for run in secure_runs
            ),
            "dds_f1": summarize(
                [run["authorization"]["f1"] for run in dds_runs]
            ),
            "dds_p95_us": summarize(
                [run["performance"]["p95_us"] for run in dds_runs]
            ),
        },
        "NP002": {
            "detection_f1": acoustic["detection"]["f1"],
            "type_macro_f1": acoustic["type_classification"]["macro_f1"],
            "held_out_type_macro_f1": summarize(
                [
                    fold["type_macro_f1"]
                    for fold in acoustic["recording_level_folds"]
                ]
            ),
            "held_out_detection_f1": summarize(
                [
                    fold["detection_f1"]
                    for fold in acoustic["recording_level_folds"]
                ]
            ),
        },
        "NV061": {
            "tracks": opensky["tracks"],
            "forecast_intervals": opensky["forecast_intervals"],
            "improvement_vs_hold_pct": opensky["improvement_vs_hold_pct"],
            "forecast_rmse_km": opensky["forecast_rmse_km"],
        },
    }
    return result


def render(result: dict) -> str:
    return f"""# Third-Wave Robustness

| Area | Result |
| --- | --- |
| Secure OPC UA | success minimum {result["NV059"]["secure_opcua_success_rate"]["minimum"]:.3f}; unsecured rejection rate {result["NV059"]["unsecured_rejection_rate"]:.3f}; p95 maximum {result["NV059"]["secure_opcua_p95_us"]["maximum"]:.1f} us |
| Cyclone DDS | authorization F1 minimum {result["NV059"]["dds_f1"]["minimum"]:.3f}; p95 maximum {result["NV059"]["dds_p95_us"]["maximum"]:.1f} us |
| NASA acoustic detection | aggregate F1 {result["NP002"]["detection_f1"]:.3f}; held-out fold minimum {result["NP002"]["held_out_detection_f1"]["minimum"]:.3f} |
| NASA four-type classification | aggregate macro-F1 {result["NP002"]["type_macro_f1"]:.3f}; held-out fold minimum {result["NP002"]["held_out_type_macro_f1"]["minimum"]:.3f} |
| Live OpenSky forecasting | {result["NV061"]["tracks"]} held-out tracks; {result["NV061"]["forecast_intervals"]} intervals; {result["NV061"]["improvement_vs_hold_pct"]:.1f}% improvement over hold |
"""


def main() -> None:
    result = run()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    write_json(OUTPUT / "wave3_robustness.json", result)
    (OUTPUT / "WAVE3_ROBUSTNESS.md").write_text(render(result))
    print(render(result))
    print(json.dumps({"output": str(OUTPUT)}, indent=2))


if __name__ == "__main__":
    main()
