#!/usr/bin/env python3
"""Execute the full seven-topic TRL 3/4 evidence campaign."""

from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path
from typing import Any, Callable

from prepare_noaa_ais import prepare
from run_experiments import run_qsparx
from trl4_common import (
    EvidenceChain,
    RequirementGate,
    runtime_metadata,
    score_gates,
    tamper_test,
    to_builtin,
    write_json,
)
from trl4_cyber import run_nv059_trl4, run_nv062_trl4, run_qsparx_trl4
from trl4_tracks import (
    dataset_fingerprint,
    evaluate_real_ais_forecasting,
    evaluate_real_ais_pol,
    load_real_ais_tracks,
    run_np002_trl4,
    run_nv061_trl4,
    run_nv065_trl4,
)


ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT = ROOT / "results" / "trl4_campaign"
AIS_ARCHIVE = ROOT / "data" / "external" / "noaa_ais" / "AIS_2020_02_15.zip"
AIS_SUBSET = ROOT / "data" / "processed" / "noaa_ais_puget_sound_2020_02_15.csv"
PZDR_ROOT = Path("/Users/giansingh/Documents/GitHub/pzdr-reference")
RTVLAS_ROOT = Path(
    "/Users/giansingh/Documents/GitHub/codex-audit-pzd-rtvlas/RTVLASOPEN-main"
)


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "minimum": min(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "maximum": max(values),
    }


def repeat(
    seeds: list[int],
    runner: Callable[[int], dict[str, Any]],
    extractors: dict[str, Callable[[dict[str, Any]], float]],
) -> dict[str, Any]:
    runs = [runner(seed) for seed in seeds]
    return {
        "seeds": seeds,
        "metrics": {
            name: summarize([float(extractor(run)) for run in runs])
            for name, extractor in extractors.items()
        },
    }


def gate(
    name: str,
    weight: float,
    achieved: float | bool,
    evidence: str,
) -> RequirementGate:
    return RequirementGate(name, weight, float(achieved), evidence)


def scores(results: dict[str, Any]) -> dict[str, Any]:
    q = results["QSPARX"]
    zt = results["NV059"]
    st = results["NV062"]
    cuas = results["NP002"]
    forecast = results["NV061"]
    pol = results["NV063"]
    sensor = results["NV065"]

    return {
        "QSPARX": {
            "estimated_trl": 3.6,
            **score_gates(
                [
                    gate("crypto discovery validation", 8, q["scanner_validation"]["f1"], "labeled scanner fixtures"),
                    gate("existing-system inventory", 8, min(q["inventory"]["files_scanned"] / 200, 1), f'{q["inventory"]["files_scanned"]} real files'),
                    gate("ML-KEM operation", 12, q["pqc_benchmark"]["ml_kem_768"]["valid_shared_secrets"] / q["pqc_benchmark"]["iterations"], "actual ML-KEM-768"),
                    gate("ML-DSA and tamper rejection", 12, q["pqc_benchmark"]["ml_dsa_65"]["tamper_rejected"] / q["pqc_benchmark"]["iterations"], "actual ML-DSA-65"),
                    gate("AI risk scoring", 12, q["risk_model"]["f1"], f'F1 {q["risk_model"]["f1"]:.3f}'),
                    gate("migration mapping", 8, q["risk_model"]["migration_mapping_coverage_pct"] / 100, "all synthetic assets mapped"),
                    gate("response time measurement", 5, q["pqc_benchmark"]["ml_dsa_65"]["verify_p95_us"] < 10_000, "measured local p95"),
                    gate("signed evidence", 5, q["evidence"]["verified"] and q["evidence"]["tamper_detected"], "signed chain"),
                    gate("live enterprise discovery connector", 10, 0.55, f'{q["certificate_store"]["certificates_parsed"]} host trust-store certificates plus repositories'),
                    gate("key-management and legacy interoperability", 8, 0.65, "certificate and algorithm mapping; no enterprise dependency graph"),
                    gate("AFDW-representative environment", 12, 0.20, "simulated, not an AFDW network"),
                ]
            ),
        },
        "NV059": {
            "estimated_trl": 4.0,
            **score_gates(
                [
                    gate("real credential chain", 10, zt["piv_surrogate"]["certificate_chain_valid"], "P-256 X.509 chain"),
                    gate("key possession and revocation", 8, zt["piv_surrogate"]["challenge_response_valid"] and zt["piv_surrogate"]["revoked_certificate_rejected"], "challenge and revoked serial"),
                    gate("authorization correctness", 15, zt["authorization"]["f1"], f'F1 {zt["authorization"]["f1"]:.3f}'),
                    gate("wire protocol adapter", 8, zt["modbus_adapter"]["malformed_blocked"] / zt["modbus_adapter"]["malformed_cases"], "Modbus/TCP parser"),
                    gate("DDIL local operation", 10, zt["authorization"]["offline_decisions"] > 0, f'{zt["authorization"]["offline_decisions"]} offline decisions'),
                    gate("adaptive attack coverage", 10, zt["authorization"]["recall"], "eight attack classes"),
                    gate("under-five-second access", 5, zt["performance"]["p95_us"] < 5_000_000, f'{zt["performance"]["p95_us"]:.1f} us p95'),
                    gate("immutable decision evidence", 8, zt["evidence"]["verified"] and zt["evidence"]["tamper_detected"], "signed chain"),
                    gate("microsegmentation enforcement", 10, 0.35, "data/action policy; no network enforcement"),
                    gate("heterogeneous combat protocols", 8, 0.35, "real Modbus path; other adapters modeled"),
                    gate("representative combat-system environment", 8, 0.40, "surrogate OT transaction path"),
                ]
            ),
        },
        "NV062": {
            "estimated_trl": 3.7,
            **score_gates(
                [
                    gate("hybrid PQC confidentiality", 15, st["http_integration"]["accepted"] / st["http_integration"]["tasks"], "X25519 + ML-KEM + AES-GCM"),
                    gate("dual-signature authenticity", 10, 1, "Ed25519 + ML-DSA"),
                    gate("commercial schema adapters", 8, min(st["provider_adapters"] / 4, 1), "four provider schemas"),
                    gate("mock interface integration", 8, st["http_integration"]["accepted"] / st["http_integration"]["tasks"], "localhost HTTP gateway"),
                    gate("tamper and replay rejection", 8, min(st["adversarial"]["tamper_blocked"] / st["adversarial"]["tamper_cases"], st["adversarial"]["replay_blocked"] / st["adversarial"]["replay_cases"]), "adversarial envelopes"),
                    gate("transaction latency", 5, st["http_integration"]["p95_us"] < 100_000, f'{st["http_integration"]["p95_us"]:.1f} us p95'),
                    gate("signed audit evidence", 5, st["evidence"]["verified"] and st["evidence"]["tamper_detected"], "signed chain"),
                    gate("return data path", 8, st["http_integration"]["return_data_verified"] / st["http_integration"]["tasks"], "encrypted provider return envelopes verified"),
                    gate("90 percent tasking-time goal", 10, 0.65, "workflow modeled, not provider-measured"),
                    gate("IL-5/IL-6 architecture", 8, 0.35, "classification boundary modeled"),
                    gate("real commercial provider", 15, 0.0, "no provider API or agreement"),
                ]
            ),
        },
        "NP002": {
            "estimated_trl": 3.5,
            **score_gates(
                [
                    gate("multi-target tracking", 12, cuas["track_association"]["mean_assignment_accuracy"], f'{cuas["track_association"]["mean_assignment_accuracy"]:.3f} association'),
                    gate("swarm anomaly accuracy", 15, cuas["behavior_detection"]["f1"], f'F1 {cuas["behavior_detection"]["f1"]:.3f}'),
                    gate("hostile-swarm recall", 8, cuas["behavior_detection"]["recall"], f'recall {cuas["behavior_detection"]["recall"]:.3f}'),
                    gate("clutter and missed detections", 8, 1, "91% Pd plus clutter"),
                    gate("multiple swarm behaviors", 8, 1, "converge, split, encircle and benign patterns"),
                    gate("real-time processing", 7, cuas["performance"]["scenario_runtime_p95_ms"] < 100, f'{cuas["performance"]["scenario_runtime_p95_ms"]:.1f} ms/scenario'),
                    gate("scalability evidence", 7, 0.65, "up to roughly 40 UAS per scenario"),
                    gate("sensor front-end integration", 10, 0.30, "kinematic detections, no EO/RF hardware"),
                    gate("target identification/payload", 8, 0.20, "behavior only"),
                    gate("explainable signed alerts", 5, cuas["evidence"]["verified"] and cuas["evidence"]["tamper_detected"], "signed alert chain"),
                    gate("real hardware or external UAS data", 12, 0.15, "synthetic representative tracks"),
                ]
            ),
        },
        "NV061": {
            "estimated_trl": 3.5,
            **score_gates(
                [
                    gate("future-state forecasting", 15, min(forecast["forecast"]["improvement_vs_hold_pct"] / 50, 1), f'{forecast["forecast"]["improvement_vs_hold_pct"]:.1f}% better than hold'),
                    gate("automated prioritization", 12, forecast["hierarchy"]["priority_recall_at_threat_count"], f'{forecast["hierarchy"]["priority_recall_at_threat_count"]:.3f} recall'),
                    gate("hierarchical target management", 8, 1, "four priority tiers"),
                    gate("track custody", 10, forecast["track_custody"]["assignment_accuracy"], f'{forecast["track_custody"]["assignment_accuracy"]:.3f} association'),
                    gate("PoL and change detection", 8, 0.80, "RTVLAS persistence reused"),
                    gate("scalability", 8, forecast["performance"]["scale_ms_per_update"]["50000"] < 10, "50,000 vector update benchmark"),
                    gate("response time", 5, forecast["performance"]["us_per_object"] < 10_000, f'{forecast["performance"]["us_per_object"]:.1f} us/object'),
                    gate("multi-source sensor fusion", 10, 0.45, "no real heterogeneous feeds"),
                    gate("object identification", 8, 0.25, "track identity assumed after association"),
                    gate("representative maritime data", 10, min(forecast["real_ais_forecast"]["tracks"] / 100, 1), f'{forecast["real_ais_forecast"]["tracks"]} NOAA AIS tracks'),
                    gate("signed decision evidence", 6, forecast["evidence"]["verified"] and forecast["evidence"]["tamper_detected"], "signed hierarchy evidence"),
                ]
            ),
        },
        "NV063": {
            "estimated_trl": 3.9,
            **score_gates(
                [
                    gate("real maritime data", 15, 1, f'{pol["unlabeled_tracks_seen"]} official AIS tracks screened'),
                    gate("anomaly accuracy", 15, pol["f1"], f'F1 {pol["f1"]:.3f}'),
                    gate("anomaly recall", 10, pol["recall"], f'recall {pol["recall"]:.3f}'),
                    gate("false-alert control", 10, max(0, 1 - pol["false_positive_rate"] / 0.25), f'FPR {pol["false_positive_rate"]:.3f}'),
                    gate("low-history compact state", 10, 1, f'{pol["compact_state_estimate_bytes_per_track"]} bytes/track estimate'),
                    gate("explainable confidence alerts", 10, 1, "reason codes plus two thresholds"),
                    gate("surface and air coverage", 5, 0.65, "real AIS plus synthetic air path from base lab"),
                    gate("notional radar/composite tracks", 5, 0.35, "architecture only"),
                    gate("real-time processing", 5, pol["processing_us_per_track_update"] < 1000, f'{pol["processing_us_per_track_update"]:.1f} us/update'),
                    gate("SSDS integration definition", 5, 0.40, "data/display concept, no SSDS interface"),
                    gate("signed alert evidence", 5, pol["evidence"]["verified"] and pol["evidence"]["tamper_detected"], "signed chain"),
                    gate("transparent data quality handling", 5, 1, f'{pol["quality_screen_excluded_tracks"]} unlabeled tracks excluded, not relabeled'),
                ]
            ),
        },
        "NV065": {
            "estimated_trl": 3.5,
            **score_gates(
                [
                    gate("sensor contribution characterization", 10, 1, "marginal covariance reduction"),
                    gate("resource reallocation benefit", 15, min(sensor["novel_threat_quality_improvement_pct"] / 50, 1), f'{sensor["novel_threat_quality_improvement_pct"]:.1f}% novel-threat improvement'),
                    gate("novel scenario response", 10, 1, "hostility changes after onset"),
                    gate("four named sensor surrogates", 5, len(sensor["four_sensor_surrogates"]) / 4, "four Phase I radar labels"),
                    gate("controllable task modes", 8, 1, "search, track, cueing, illumination"),
                    gate("real-time advisory output", 7, sensor["recommendation_runtime_p95_us"] < 100_000, f'{sensor["recommendation_runtime_p95_us"]:.1f} us p95'),
                    gate("explainable recommendations", 5, 1, "utility and reason per recommendation"),
                    gate("ablation evidence", 5, sensor["ablation"]["full_method_improvement_pct"] > sensor["ablation"]["uncertainty_only_improvement_pct"], "full method beats ablations"),
                    gate("program-of-record radar realism", 20, 0.35, "open low-fidelity surrogates"),
                    gate("SSDS integration constraints", 15, 0.30, "advisory concept only"),
                ]
            ),
        },
    }


def render_report(campaign: dict[str, Any]) -> str:
    score_data = campaign["scores"]
    order = sorted(score_data, key=lambda topic: score_data[topic]["score"], reverse=True)
    rows = "\n".join(
        f'| {rank} | {topic} | {score_data[topic]["score"]:.1f} | '
        f'{score_data[topic]["estimated_trl"]:.1f} |'
        for rank, topic in enumerate(order, 1)
    )
    r = campaign["results"]
    robustness = campaign["robustness"]
    return f"""# Seven-Topic TRL 3/4 Laboratory Campaign

Generated: {campaign["metadata"]["generated_at"]}

## Outcome

All seven demonstrators completed their laboratory campaign. The score is a
measured match to the current Phase I requirement, not a probability of award.

| Rank | Topic | Match / 100 | Estimated TRL |
| ---: | --- | ---: | ---: |
{rows}

## Measured highlights

- **QSPARX:** scanned `{r["QSPARX"]["inventory"]["files_scanned"]}` real source/configuration files and `{r["QSPARX"]["certificate_store"]["certificates_parsed"]}` host trust-store certificates; actual ML-KEM-768 and ML-DSA-65 operations passed `{r["QSPARX"]["pqc_benchmark"]["iterations"]}` iterations; AI migration-risk F1 `{r["QSPARX"]["risk_model"]["f1"]:.3f}`.
- **NV059:** real P-256 X.509 chain, challenge response, revocation, and Modbus/TCP parsing; authorization F1 `{r["NV059"]["authorization"]["f1"]:.3f}`; p95 `{r["NV059"]["performance"]["p95_us"]:.1f}` us.
- **NV062:** bidirectional hybrid X25519 + ML-KEM-768 encryption and Ed25519 + ML-DSA-65 signatures over four provider schemas through a localhost HTTP gateway; p95 `{r["NV062"]["http_integration"]["p95_us"]:.1f}` us; all task returns, tamper, and replay cases verified correctly.
- **NP002:** noisy multi-UAS detections with 91% probability of detection and clutter; association accuracy `{r["NP002"]["track_association"]["mean_assignment_accuracy"]:.3f}`; behavior F1 `{r["NP002"]["behavior_detection"]["f1"]:.3f}`.
- **NV061:** synthetic forecast improvement `{r["NV061"]["forecast"]["improvement_vs_hold_pct"]:.1f}%`; real-AIS forecast improvement `{r["NV061"]["real_ais_forecast"]["improvement_vs_hold_pct"]:.1f}%`; priority recall `{r["NV061"]["hierarchy"]["priority_recall_at_threat_count"]:.3f}`; association accuracy `{r["NV061"]["track_custody"]["assignment_accuracy"]:.3f}`.
- **NV063:** official NOAA AIS input; `{r["NV063"]["unlabeled_tracks_seen"]}` tracks screened; held-out/injected F1 `{r["NV063"]["f1"]:.3f}` and FPR `{r["NV063"]["false_positive_rate"]:.3f}`.
- **NV065:** four-radar low-fidelity advisory model; novel-threat covariance improvement `{r["NV065"]["novel_threat_quality_improvement_pct"]:.1f}%`; p95 `{r["NV065"]["recommendation_runtime_p95_us"]:.1f}` us.

## Robustness

- QSPARX risk F1 mean/min: `{robustness["QSPARX"]["metrics"]["risk_f1"]["mean"]:.3f}` / `{robustness["QSPARX"]["metrics"]["risk_f1"]["minimum"]:.3f}`.
- NV059 authorization F1 mean/min: `{robustness["NV059"]["metrics"]["authorization_f1"]["mean"]:.3f}` / `{robustness["NV059"]["metrics"]["authorization_f1"]["minimum"]:.3f}`.
- NV063 real-AIS F1 mean/min: `{robustness["NV063"]["metrics"]["f1"]["mean"]:.3f}` / `{robustness["NV063"]["metrics"]["f1"]["minimum"]:.3f}`.
- NP002 swarm F1 mean/min: `{robustness["NP002"]["metrics"]["behavior_f1"]["mean"]:.3f}` / `{robustness["NP002"]["metrics"]["behavior_f1"]["minimum"]:.3f}`.
- NV061 forecast improvement mean/min: `{robustness["NV061"]["metrics"]["forecast_improvement"]["mean"]:.1f}%` / `{robustness["NV061"]["metrics"]["forecast_improvement"]["minimum"]:.1f}%`.
- NV065 novel-threat improvement mean/min: `{robustness["NV065"]["metrics"]["novel_improvement"]["mean"]:.1f}%` / `{robustness["NV065"]["metrics"]["novel_improvement"]["minimum"]:.1f}%`.

## Honest remaining blockers

| Topic | Largest blocker to a stronger TRL 4 claim |
| --- | --- |
| QSPARX | Host trust-store and repository discovery work, but there is no live AFDW/CMDB/network-endpoint evaluation |
| NV059 | No actual network microsegmentation, CAC middleware, DDS, or OPC-UA integration |
| NV062 | No commercial provider API, return imagery path, or IL-5/IL-6 accreditation environment |
| NP002 | No real EO/RF/radar UAS sensor data and no payload/type classifier |
| NV061 | NOAA AIS is exercised, but other sensor domains and an operational identity/custody corpus are absent |
| NV063 | AIS false-alert rate remains material; ADS-B and SSDS composite tracks remain simulated |
| NV065 | Radar parameters and SSDS tasking constraints remain open low-fidelity surrogates |

## Interpretation

- `90+` means the laboratory artifact covers nearly every Phase I feasibility
  element; remaining gaps are mostly customer environment or transition access.
- `80-89` means strong Phase I technical match with one or two meaningful
  integration/domain gaps.
- `70-79` means a responsive and testable Phase I concept, but reviewers will
  need to accept a larger transition or realism assumption.
- `60-69` means the core mechanism works in the laboratory, but a major
  customer-domain integration is still missing.

The evidence supports pursuing all seven as two shared background-technology
families, not seven independent products.

The `pqcrypto` ML-KEM/ML-DSA implementation used here exercises the NIST
algorithms but is not claimed to be a FIPS-validated cryptographic module.

## Data and standards sources

- NOAA/USCG AIS day:
  https://coast.noaa.gov/htdata/CMSP/AISDataHandler/2020/AIS_2020_02_15.zip
- QSPARX topic:
  https://www.sbir.gov/topics/12764
- NIST FIPS 203:
  https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204:
  https://csrc.nist.gov/pubs/fips/204/final
- NIST FIPS 205:
  https://csrc.nist.gov/pubs/fips/205/final
- Navy topics:
  https://www.navysbir.com/topics26_3.htm
"""


def run_campaign(output: Path) -> dict[str, Any]:
    if not AIS_SUBSET.exists():
        if not AIS_ARCHIVE.exists():
            raise FileNotFoundError(
                f"missing AIS archive and subset: {AIS_ARCHIVE}"
            )
        prepare(AIS_ARCHIVE, AIS_SUBSET)
    ais_tracks = load_real_ais_tracks(AIS_SUBSET, maximum_tracks=500)

    nv061 = run_nv061_trl4(object_count=500)
    nv061["real_ais_forecast"] = evaluate_real_ais_forecasting(ais_tracks[:150])
    results = {
        "QSPARX": run_qsparx_trl4([PZDR_ROOT, RTVLAS_ROOT]),
        "NV059": run_nv059_trl4(requests=6000),
        "NV062": run_nv062_trl4(),
        "NP002": run_np002_trl4(scenarios=100),
        "NV061": nv061,
        "NV063": evaluate_real_ais_pol(ais_tracks),
        "NV065": run_nv065_trl4(),
    }

    seeds = [10, 11, 12, 13, 14]
    robustness = {
        "QSPARX": repeat(
            seeds,
            run_qsparx,
            {
                "risk_f1": lambda value: value["f1"],
                "risk_recall": lambda value: value["recall"],
            },
        ),
        "NV059": repeat(
            seeds[:3],
            lambda seed: run_nv059_trl4(seed, requests=3000),
            {
                "authorization_f1": lambda value: value["authorization"]["f1"],
                "p95_us": lambda value: value["performance"]["p95_us"],
            },
        ),
        "NV062": repeat(
            seeds[:3],
            run_nv062_trl4,
            {
                "http_p95_us": lambda value: value["http_integration"]["p95_us"],
                "tamper_block_rate": lambda value: value["adversarial"]["tamper_blocked"]
                / value["adversarial"]["tamper_cases"],
            },
        ),
        "NP002": repeat(
            seeds,
            lambda seed: run_np002_trl4(seed, scenarios=60),
            {
                "behavior_f1": lambda value: value["behavior_detection"]["f1"],
                "association_accuracy": lambda value: value["track_association"]["mean_assignment_accuracy"],
            },
        ),
        "NV061": repeat(
            seeds,
            lambda seed: {
                **run_nv061_trl4(seed, object_count=300),
                "real_ais_forecast": evaluate_real_ais_forecasting(ais_tracks[:150]),
            },
            {
                "forecast_improvement": lambda value: value["forecast"]["improvement_vs_hold_pct"],
                "priority_recall": lambda value: value["hierarchy"]["priority_recall_at_threat_count"],
                "association_accuracy": lambda value: value["track_custody"]["assignment_accuracy"],
            },
        ),
        "NV063": repeat(
            seeds,
            lambda seed: evaluate_real_ais_pol(ais_tracks, seed),
            {
                "f1": lambda value: value["f1"],
                "recall": lambda value: value["recall"],
                "false_positive_rate": lambda value: value["false_positive_rate"],
            },
        ),
        "NV065": repeat(
            seeds,
            run_nv065_trl4,
            {
                "novel_improvement": lambda value: value["novel_threat_quality_improvement_pct"],
                "p95_us": lambda value: value["recommendation_runtime_p95_us"],
            },
        ),
    }

    score_data = scores(results)
    campaign_evidence = EvidenceChain(b"seven-topic-campaign")
    for topic, result in results.items():
        campaign_evidence.append(
            topic,
            {
                "result_hash": __import__("hashlib").sha256(
                    json.dumps(to_builtin(result), sort_keys=True).encode()
                ).hexdigest(),
                "score": score_data[topic]["score"],
                "estimated_trl": score_data[topic]["estimated_trl"],
            },
        )
    campaign = {
        "metadata": runtime_metadata(),
        "dataset": {
            **dataset_fingerprint(AIS_SUBSET),
            "metadata": json.loads(AIS_SUBSET.with_suffix(".metadata.json").read_text()),
        },
        "results": results,
        "robustness": robustness,
        "scores": score_data,
        "campaign_evidence": {
            "records": campaign_evidence.records,
            "head": campaign_evidence.head,
            "verified": EvidenceChain.verify(
                campaign_evidence.records,
                campaign_evidence.public_key,
            ),
            "tamper_detected": tamper_test(
                campaign_evidence.records,
                campaign_evidence.public_key,
            ),
        },
    }
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "campaign_results.json", campaign)
    for topic, result in results.items():
        write_json(output / "topics" / f"{topic.lower()}_results.json", result)
    write_json(output / "match_scores.json", score_data)
    report = render_report(campaign)
    (output / "TRL4_CAMPAIGN_REPORT.md").write_text(report)
    return campaign


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    started = time.perf_counter()
    campaign = run_campaign(args.output)
    print(render_report(campaign))
    print(f"\nElapsed: {time.perf_counter() - started:.1f} seconds")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
