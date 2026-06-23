#!/usr/bin/env python3
"""Repeat the fifth-wave numerical experiments and report their floors."""

from __future__ import annotations

import json
import statistics
from pathlib import Path

from run_wave5_campaign import AIS_PATH, OPENSKY_LONG
from trl4_common import write_json
from trl4_tracks import load_real_ais_tracks
from trl4_wave5 import (
    run_beam_revisit_scheduler,
    run_composite_track_contract_v2,
    run_long_cross_domain_pol,
    run_qsparx_migration_execution,
    run_surface_track_classifier_cv,
)


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "results" / "trl4_wave5"


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "minimum": min(values),
        "mean": statistics.fmean(values),
        "maximum": max(values),
    }


def run() -> dict:
    tracks = load_real_ais_tracks(AIS_PATH, maximum_tracks=500)
    surface_runs = [
        run_surface_track_classifier_cv(tracks, seed=6308 + seed)
        for seed in range(3)
    ]
    air_runs = [
        run_long_cross_domain_pol(OPENSKY_LONG, seed=6306 + seed)
        for seed in range(5)
    ]
    radar_runs = [
        run_beam_revisit_scheduler(seed=6507 + seed)
        for seed in range(5)
    ]
    range_runs = [
        run_qsparx_migration_execution(12)
        for _ in range(2)
    ]
    interface = run_composite_track_contract_v2(20_000)
    return {
        "QSPARX": {
            "inventory_accuracy": summarize(
                [
                    run["active_endpoint_inventory_accuracy"]
                    for run in range_runs
                ]
            ),
            "migration_complete_rate": statistics.fmean(
                float(run["migration_order_complete"]) for run in range_runs
            ),
            "keystores_parsed": summarize(
                [float(run["pkcs12_keystores_parsed"]) for run in range_runs]
            ),
        },
        "NV063": {
            "surface_f1": summarize([run["f1"] for run in surface_runs]),
            "surface_recall": summarize(
                [run["recall"] for run in surface_runs]
            ),
            "surface_minimum_fold_f1": summarize(
                [run["minimum_fold_f1"] for run in surface_runs]
            ),
            "air_f1": summarize([run["f1"] for run in air_runs]),
            "air_fpr": summarize(
                [run["false_positive_rate"] for run in air_runs]
            ),
            "interface_tamper_rate": interface["tamper_rejected"]
            / interface["tamper_cases"],
            "interface_old_version_rejection": interface[
                "old_versions_rejected"
            ]
            / interface["old_version_cases"],
        },
        "NV065": {
            "invalid_schedules": summarize(
                [float(run["invalid_schedules"]) for run in radar_runs]
            ),
            "missed_revisit_deadlines": summarize(
                [
                    float(run["missed_revisit_deadlines"])
                    for run in radar_runs
                ]
            ),
            "scheduler_p95_us": summarize(
                [run["p95_scheduler_us"] for run in radar_runs]
            ),
        },
    }


def render(result: dict) -> str:
    return f"""# Fifth-Wave Robustness

| Topic | Robustness floor |
| --- | --- |
| QSPARX | endpoint inventory minimum {result["QSPARX"]["inventory_accuracy"]["minimum"]:.3f}; migration completion {result["QSPARX"]["migration_complete_rate"]:.3f}; keystores minimum {result["QSPARX"]["keystores_parsed"]["minimum"]:.0f} |
| NV063 surface | F1 minimum {result["NV063"]["surface_f1"]["minimum"]:.3f}; recall minimum {result["NV063"]["surface_recall"]["minimum"]:.3f}; worst fold F1 minimum {result["NV063"]["surface_minimum_fold_f1"]["minimum"]:.3f} |
| NV063 air/interface | air F1 minimum {result["NV063"]["air_f1"]["minimum"]:.3f}; FPR maximum {result["NV063"]["air_fpr"]["maximum"]:.3f}; tamper and old-version rejection {result["NV063"]["interface_tamper_rate"]:.3f}/{result["NV063"]["interface_old_version_rejection"]:.3f} |
| NV065 | invalid schedules maximum {result["NV065"]["invalid_schedules"]["maximum"]:.0f}; missed deadlines maximum {result["NV065"]["missed_revisit_deadlines"]["maximum"]:.0f}; scheduler p95 maximum {result["NV065"]["scheduler_p95_us"]["maximum"]:.1f} us |
"""


def main() -> None:
    result = run()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    write_json(OUTPUT / "wave5_robustness.json", result)
    (OUTPUT / "WAVE5_ROBUSTNESS.md").write_text(render(result))
    print(render(result))
    print(json.dumps({"output": str(OUTPUT)}, indent=2))


if __name__ == "__main__":
    main()
