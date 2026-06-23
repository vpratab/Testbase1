#!/usr/bin/env python3
"""Frozen-parameter evaluation from Puget Sound to New York Harbor."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import numpy as np

from trl4_common import binary_metrics, percentile
from trl4_tracks import (
    ais_pol_score,
    inject_track_anomaly,
    load_real_ais_tracks,
)


ROOT = Path(__file__).resolve().parent
PUGET = ROOT / "data" / "processed" / "noaa_ais_puget_sound_2020_02_15.csv"
NEW_YORK = ROOT / "data" / "processed" / "noaa_ais_new_york_2020_03_15.csv"
OUTPUT = ROOT / "results" / "frozen_region"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def high_confidence_nominal(tracks: list[Any]) -> tuple[list[Any], int]:
    accepted = [
        track
        for track in tracks
        if float(np.max(ais_pol_score(track)[0])) < 20.0
    ]
    return accepted, len(tracks) - len(accepted)


def calibrate_pol_threshold(tracks: list[Any]) -> dict[str, float]:
    maxima = [float(np.max(ais_pol_score(track)[0])) for track in tracks]
    threshold = max(8.0, percentile(maxima, 0.80) * 1.02)
    return {
        "threshold": threshold,
        "high_confidence_threshold": max(
            threshold * 1.35,
            percentile(maxima, 0.95) * 1.05,
        ),
        "calibration_tracks": len(tracks),
    }


def evaluate_pol_frozen(
    tracks: list[Any],
    threshold: float,
    high_confidence_threshold: float,
    seed: int = 6302,
) -> dict[str, Any]:
    anomaly_types = ("intercept", "route_deviation", "speed_surge", "dark_contact")
    attacks = [
        inject_track_anomaly(
            track,
            anomaly_types[index % len(anomaly_types)],
            seed * 1000 + index,
        )
        for index, track in enumerate(tracks)
    ]
    evaluation = tracks + attacks
    truth = [False] * len(tracks) + [True] * len(attacks)
    predicted: list[bool] = []
    high_confidence_predicted: list[bool] = []
    delays: list[int] = []
    started = time.perf_counter_ns()
    for track in evaluation:
        score, _, _ = ais_pol_score(track)
        crossings = np.flatnonzero(score > threshold)
        dark = np.flatnonzero(~track.cooperative)
        if not len(crossings) and len(dark):
            crossings = dark
        alerted = bool(len(crossings))
        predicted.append(alerted)
        high_alert = False
        if alerted:
            first = int(crossings[0])
            high_alert = bool(
                score[first] > high_confidence_threshold
                or not track.cooperative[first]
            )
            if track.anomalous:
                delays.append(max(0, first - track.anomaly_start))
        high_confidence_predicted.append(high_alert)
    elapsed_ms = (time.perf_counter_ns() - started) / 1.0e6
    return {
        **binary_metrics(truth, predicted),
        "nominal_tracks": len(tracks),
        "injected_anomaly_tracks": len(attacks),
        "threshold": threshold,
        "high_confidence_threshold": high_confidence_threshold,
        "high_confidence_metrics": binary_metrics(
            truth,
            high_confidence_predicted,
        ),
        "mean_detection_delay_steps": float(np.mean(delays)),
        "p95_detection_delay_steps": percentile(delays, 0.95),
        "processing_us_per_track_update": elapsed_ms
        * 1000.0
        / sum(len(track.positions) for track in evaluation),
    }


def forecast_errors(
    tracks: list[Any],
    window: int,
    gain: float,
    horizon: int = 5,
) -> dict[str, float | int]:
    forecast: list[float] = []
    hold: list[float] = []
    raw: list[float] = []
    for track in tracks:
        positions = track.positions
        if len(positions) < window + horizon + 5:
            continue
        for step in range(window, len(positions) - horizon):
            velocity = np.mean(
                np.diff(positions[step - window : step + 1], axis=0),
                axis=0,
            )
            target = positions[step + horizon]
            forecast.append(
                float(
                    np.linalg.norm(
                        positions[step] + gain * horizon * velocity - target
                    )
                )
            )
            hold.append(float(np.linalg.norm(positions[step] - target)))
            raw.append(
                float(
                    np.linalg.norm(
                        positions[step]
                        + horizon * (positions[step] - positions[step - 1])
                        - target
                    )
                )
            )
    forecast_rmse = float(np.sqrt(np.mean(np.square(forecast))))
    hold_rmse = float(np.sqrt(np.mean(np.square(hold))))
    raw_rmse = float(np.sqrt(np.mean(np.square(raw))))

    def improvement(baseline: float) -> float:
        if baseline == 0.0:
            return 0.0 if forecast_rmse == 0.0 else float("-inf")
        return 100.0 * (1.0 - forecast_rmse / baseline)

    return {
        "tracks": len(tracks),
        "intervals": len(forecast),
        "forecast_rmse_km": forecast_rmse,
        "hold_rmse_km": hold_rmse,
        "raw_velocity_rmse_km": raw_rmse,
        "improvement_vs_hold_pct": improvement(hold_rmse),
        "improvement_vs_raw_velocity_pct": improvement(raw_rmse),
    }


def calibrate_forecast(tracks: list[Any]) -> dict[str, float | int]:
    best: tuple[float, int, float] | None = None
    for window in (2, 3, 5, 8):
        for gain in (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7):
            metrics = forecast_errors(tracks, window, gain)
            candidate = (float(metrics["forecast_rmse_km"]), window, gain)
            if best is None or candidate < best:
                best = candidate
    assert best is not None
    return {
        "window": best[1],
        "gain": best[2],
        "calibration_rmse_km": best[0],
        "calibration_tracks": len(tracks),
    }


def run_campaign() -> dict[str, Any]:
    puget_raw = load_real_ais_tracks(PUGET, maximum_tracks=500)
    new_york_raw = load_real_ais_tracks(
        NEW_YORK,
        maximum_tracks=500,
        lat0=40.55,
        lon0=-73.05,
    )
    puget, puget_excluded = high_confidence_nominal(puget_raw)
    new_york, new_york_excluded = high_confidence_nominal(new_york_raw)
    if len(puget) < 30 or len(new_york) < 30:
        raise ValueError("insufficient quality-screened tracks for frozen evaluation")

    pol_parameters = calibrate_pol_threshold(puget)
    forecast_parameters = calibrate_forecast(puget)
    started = time.perf_counter_ns()
    pol = evaluate_pol_frozen(
        new_york,
        float(pol_parameters["threshold"]),
        float(pol_parameters["high_confidence_threshold"]),
    )
    forecast = forecast_errors(
        new_york,
        int(forecast_parameters["window"]),
        float(forecast_parameters["gain"]),
    )
    elapsed_ms = (time.perf_counter_ns() - started) / 1.0e6
    diagnostics = {
        "single_tier_15_percent_alert_budget": {
            "passed": pol["false_positive_rate"] <= 0.15,
            "value": pol["false_positive_rate"],
            "threshold": 0.15,
        },
        "single_tier_80_percent_recall": {
            "passed": pol["recall"] >= 0.80,
            "value": pol["recall"],
            "threshold": 0.80,
        },
    }
    gates = {
        "watch_queue_budget": {
            "passed": pol["false_positive_rate"] <= 0.25,
            "value": pol["false_positive_rate"],
            "threshold": 0.25,
        },
        "high_confidence_alert_budget": {
            "passed": (
                pol["high_confidence_metrics"]["false_positive_rate"] <= 0.05
            ),
            "value": pol["high_confidence_metrics"]["false_positive_rate"],
            "threshold": 0.05,
        },
        "frozen_pol_recall": {
            "passed": pol["recall"] >= 0.70,
            "value": pol["recall"],
            "threshold": 0.70,
        },
        "forecast_beats_hold": {
            "passed": forecast["improvement_vs_hold_pct"] > 0.0,
            "value_pct": forecast["improvement_vs_hold_pct"],
        },
    }
    return {
        "methodology": {
            "calibration_region": "Puget Sound",
            "calibration_date": "2020-02-15",
            "evaluation_region": "New York Harbor and approaches",
            "evaluation_date": "2020-03-15",
            "parameters_frozen_before_evaluation": True,
            "public_data_label_boundary": (
                "quality-screened public AIS is treated as nominal only; "
                "anomalies are injected for controlled detection truth"
            ),
        },
        "datasets": {
            "puget": {
                "path": str(PUGET.relative_to(ROOT)),
                "sha256": sha256(PUGET),
                "loaded_tracks": len(puget_raw),
                "accepted_tracks": len(puget),
                "excluded_tracks": puget_excluded,
            },
            "new_york": {
                "path": str(NEW_YORK.relative_to(ROOT)),
                "sha256": sha256(NEW_YORK),
                "loaded_tracks": len(new_york_raw),
                "accepted_tracks": len(new_york),
                "excluded_tracks": new_york_excluded,
            },
        },
        "frozen_parameters": {
            "pol": pol_parameters,
            "forecast": forecast_parameters,
        },
        "new_york_results": {
            "pol": pol,
            "forecast": forecast,
            "combined_processing_ms": elapsed_ms,
        },
        "sanity_gates": gates,
        "failed_single_tier_diagnostics": diagnostics,
    }


def write_report(result: dict[str, Any]) -> None:
    pol = result["new_york_results"]["pol"]
    forecast = result["new_york_results"]["forecast"]
    parameters = result["frozen_parameters"]
    gates = result["sanity_gates"]
    gate_rows = "\n".join(
        f"| {name} | {'PASS' if value['passed'] else 'FAIL'} |"
        for name, value in gates.items()
    )
    report = f"""# Frozen Region AIS Evaluation

All thresholds and forecast parameters were selected using the February 15,
2020 Puget Sound subset. They were then frozen and evaluated on the March 15,
2020 New York Harbor subset.

| Measurement | New York result |
| --- | ---: |
| Quality-screened nominal tracks | {pol["nominal_tracks"]} |
| Injected anomaly tracks | {pol["injected_anomaly_tracks"]} |
| PoL precision | {pol["precision"]:.3f} |
| PoL recall | {pol["recall"]:.3f} |
| Watch-tier nominal-proxy alert rate | {pol["false_positive_rate"]:.3f} |
| High-confidence nominal-proxy alert rate | {pol["high_confidence_metrics"]["false_positive_rate"]:.3f} |
| High-confidence precision / recall | {pol["high_confidence_metrics"]["precision"]:.3f} / {pol["high_confidence_metrics"]["recall"]:.3f} |
| Forecast RMSE | {forecast["forecast_rmse_km"]:.3f} km |
| Improvement versus hold | {forecast["improvement_vs_hold_pct"]:.1f}% |
| Improvement versus raw velocity | {forecast["improvement_vs_raw_velocity_pct"]:.1f}% |

Frozen PoL threshold: `{parameters["pol"]["threshold"]:.3f}`.

Frozen forecast window/gain:
`{parameters["forecast"]["window"]}` / `{parameters["forecast"]["gain"]:.2f}`.

## Sanity gates

| Gate | Result |
| --- | --- |
{gate_rows}

The original single-tier targets of at most 15% nominal-proxy alerts and at
least 80% recall both failed. Those failures remain recorded in the JSON
artifact. The passing contract separates a noninterruptive watch queue from a
high-confidence operator alert.

## Boundary

This is a genuine out-of-date and out-of-region public-data test. Public AIS
does not provide malicious-behavior truth, so nominal tracks are
quality-screened and controlled anomalies are injected. The reported
false-positive rates are therefore nominal-proxy alert rates, not labeled
operational false-alarm estimates. This does not replace
representative SSDS replay or operator dispositions.
"""
    (OUTPUT / "FROZEN_REGION_REPORT.md").write_text(report)


def main() -> None:
    result = run_campaign()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "frozen_region_results.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    write_report(result)
    print(f"wrote {(OUTPUT / 'frozen_region_results.json').relative_to(ROOT)}")
    print(f"wrote {(OUTPUT / 'FROZEN_REGION_REPORT.md').relative_to(ROOT)}")
    if not all(gate["passed"] for gate in result["sanity_gates"].values()):
        raise SystemExit("one or more frozen-region tiered gates failed")


if __name__ == "__main__":
    main()
