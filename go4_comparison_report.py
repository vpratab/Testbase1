#!/usr/bin/env python3
"""Competitive and solicitation-alignment report for the GO-4 evidence layer."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import platform
import sys
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from go4_enhancements import (
    OUTPUT as ENHANCED_OUTPUT,
    run_all_enhanced,
)


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "results" / "go4_comparison"

OFFICIAL_SOURCES = {
    "NV059": "https://www.sbir.gov/topics/12755",
    "NV061": "https://www.sbir.gov/topics/12757",
    "NV063": "https://www.sbir.gov/topics/12759",
    "NV065": "https://www.sbir.gov/topics/12761",
    "Navy FY26 Release 3 index": "https://www.navysbir.com/topics26_3.htm",
    "NIST SP 800-207": "https://csrc.nist.gov/pubs/sp/800/207/final",
    "NIST SP 800-207A": "https://csrc.nist.gov/pubs/sp/800/207/a/final",
}

PUBLIC_BENCHMARKS = {
    "TrAISformer": {
        "source": "https://arxiv.org/html/2109.03958v4",
        "reported_result": "<10 nautical miles up to 10 hours on AIS trajectory prediction",
        "comparison_note": (
            "Long-horizon strategic trajectory forecasting; not the same as "
            "short-horizon MTC custody and priority triage."
        ),
    },
    "AIS-LLM": {
        "source": "https://arxiv.org/html/2508.07668v1",
        "reported_result": "MSE 95.76 in the paper's multi-scale maritime trajectory setup",
        "comparison_note": (
            "Large model / trained-corpus approach; useful state of art, but heavier "
            "than the deterministic tactical surrogate here."
        ),
    },
    "Two-stage BiLSTM anomaly detector": {
        "source": "https://jurnal.polibatam.ac.id/index.php/JAIC/article/view/11545",
        "reported_result": "F1 0.5709 and 9.97% false alarm rate in a maritime anomaly study",
        "comparison_note": (
            "Trained model on a particular data regime; GO-4 high-confidence tier "
            "trades recall for much lower synthetic false-positive rate."
        ),
    },
}


def _time_per_op_ns(iterations: int, fn) -> float:
    start = time.perf_counter_ns()
    for index in range(iterations):
        fn(index)
    return (time.perf_counter_ns() - start) / iterations


def profile_platform() -> dict[str, Any]:
    """Profile commodity crypto primitives used in the evidence layer."""

    hmac_key = b"assureedge-go4-hmac-key-material"
    hmac_msg = b"x" * 136
    hmac_ns = _time_per_op_ns(
        25_000,
        lambda _: hmac.new(hmac_key, hmac_msg, hashlib.sha256).digest(),
    )

    aesgcm = AESGCM(os.urandom(32))
    plaintext = b"x" * 100
    aad = b"go4-platform-profile"
    aes_ns = _time_per_op_ns(
        20_000,
        lambda index: aesgcm.encrypt(index.to_bytes(12, "big"), plaintext, aad),
    )

    signing_key = Ed25519PrivateKey.generate()
    verify_key = signing_key.public_key()
    message = hashlib.sha256(b"go4-platform-profile").digest()
    signature = signing_key.sign(message)
    sign_ns = _time_per_op_ns(3_000, lambda _: signing_key.sign(message))
    verify_ns = _time_per_op_ns(3_000, lambda _: verify_key.verify(signature, message))

    full_verify_cycle_us = (hmac_ns + aes_ns + verify_ns) / 1000.0
    full_sign_cycle_us = (hmac_ns + aes_ns + sign_ns + verify_ns) / 1000.0
    conservative_arm_scale = 2.0
    return {
        "host_platform": platform.platform(),
        "host_machine": platform.machine(),
        "python_version": sys.version.split()[0],
        "hmac_sha256_136b_us": hmac_ns / 1000.0,
        "aes_256_gcm_100b_us": aes_ns / 1000.0,
        "ed25519_sign_us": sign_ns / 1000.0,
        "ed25519_verify_us": verify_ns / 1000.0,
        "full_auth_verify_cycle_us": full_verify_cycle_us,
        "full_auth_sign_and_verify_cycle_us": full_sign_cycle_us,
        "arm_cortex_a72_estimate_us": full_verify_cycle_us * conservative_arm_scale,
        "reduction_vs_15s_current_pct": 100.0 * (1.0 - (full_verify_cycle_us / 1000.0) / 15_000.0),
        "target_under_5s_ms": 5000.0,
        "ssds_class_platform_note": (
            "Representative SSDS COTS single-board computers are commonly x86-class; "
            "this host profile is a development proxy, not target WCET evidence."
        ),
    }


def build_alignment(enhanced: dict[str, Any], platform_info: dict[str, Any]) -> dict[str, Any]:
    nv59 = enhanced["NV059"]
    nv61 = enhanced["NV061"]
    nv63 = enhanced["NV063"]
    nv65 = enhanced["NV065"]
    alignment = {
        "NV059": {
            "topic_need": "near-real-time zero trust for combat-system data",
            "kpis": {
                "authentication_under_5s": platform_info["full_auth_verify_cycle_us"] / 1000.0 < 5000.0,
                "latency_reduction_ge_50_pct": platform_info["reduction_vs_15s_current_pct"] >= 50.0,
                "unauthorized_access_reduction_ge_90_pct": nv59["attack_block_rate"] >= 0.90,
                "microsegmentation_evidence": nv59["attack_vector_stats"]["cross_compartment"]["blocked"]
                == nv59["attack_vector_stats"]["cross_compartment"]["attempts"],
                "ai_ml_behavioral_detection": nv59["behavioral_detections"] > 0,
                "degraded_operation": min(nv59["ddil_accuracy"].values()) >= 0.999,
                "immutable_logging_surrogate": nv59["chain_verified"],
                "nist_zero_trust_alignment": len(nv59["nist_sp_800_207_tenets"]) >= 5,
            },
            "remaining_external_access": [
                "DoD CAC/PKI integration",
                "DDS Security / combat-network governance",
                "CMMC Level 2 environment and sponsor-approved OT policy cases",
            ],
        },
        "NV061": {
            "topic_need": "AI-powered tracking, prediction, change detection, hierarchy, and analyst triage",
            "kpis": {
                "forecasting_beats_hold": nv61["imm_vs_hold_improvement_h5_pct"] > 50.0,
                "forecasting_beats_raw_velocity": nv61["imm_vs_raw_velocity_improvement_h5_pct"] > 0.0,
                "conformal_uncertainty_near_90": 0.86 <= nv61["conformal_coverage_h5"] <= 0.94,
                "hierarchical_target_management": sum(nv61["hierarchy"].values()) == nv61["tracks"],
                "priority_recall": nv61["priority_recall_at_threat_count"] >= 0.65,
                "modeled_response_time_improvement": nv61["modeled_analyst_time_reduction_pct"] >= 50.0,
            },
            "remaining_external_access": [
                "operational composite tracks",
                "identity truth",
                "analyst priority/disposition baselines",
            ],
        },
        "NV063": {
            "topic_need": "PoL anomaly alerts in congested maritime environments without large onboard history",
            "kpis": {
                "no_large_database": not nv63["large_historical_database_required"],
                "surface_air_360_coverage": "360-degree" in nv63["coverage"],
                "alert_content_contract": bool(nv63["sample_alerts"]),
                "watch_recall": nv63["watch_tier"]["recall"] >= 0.70,
                "high_confidence_precision": nv63["high_confidence_tier"]["precision"] >= 0.95,
                "high_confidence_fpr": nv63["high_confidence_tier"]["false_positive_rate"] <= 0.02,
                "ssds_tlr_mapping": len(nv63["ssds_tlr_mapping"]) == 3,
            },
            "remaining_external_access": [
                "SSDS replay corpus",
                "operator alert dispositions",
                "air/surface hostile behavior labels",
            ],
        },
        "NV065": {
            "topic_need": "adaptive advisory sensor tasking for fire-control-quality track improvement",
            "kpis": {
                "phase_i_sensor_suite_exact": nv65["phase_i_sensor_suite"]
                == ["SPS-48", "SPQ-9B", "MK-9 Tracker/Illuminator", "SPY-6(V)3"],
                "novel_threat_adaptation": nv65["nominal"]["novel_threat_quality_improvement_pct"] >= 50.0,
                "degraded_robustness": nv65["degraded"]["novel_threat_quality_improvement_pct"] >= 40.0,
                "burst_runtime_under_10ms": nv65["burst_stress"]["p99_runtime_us"] < 10_000.0,
                "conflicts_enforced": nv65["nominal"]["conflict_violations"] == 0
                and nv65["degraded"]["conflict_violations"] == 0,
                "ssds_tlr_mapping": len(nv65["ssds_tlr_mapping"]) == 5,
                "explainable_complexity": "O(k" in nv65["worst_case_complexity"],
            },
            "remaining_external_access": [
                "program-of-record radar parameters",
                "SSDS resource manager semantics",
                "operator confirmation workflow",
            ],
        },
    }
    for topic_alignment in alignment.values():
        topic_alignment["kpis"] = {
            name: bool(passed) for name, passed in topic_alignment["kpis"].items()
        }
    return alignment


def render_markdown(report: dict[str, Any]) -> str:
    enhanced = report["enhanced"]
    platform_info = report["platform"]
    alignment = report["alignment"]
    nv59 = enhanced["NV059"]
    nv61 = enhanced["NV061"]
    nv63 = enhanced["NV063"]
    nv65 = enhanced["NV065"]

    source_lines = "\n".join(
        f"- {name}: {url}" for name, url in report["official_sources"].items()
    )
    benchmark_lines = "\n".join(
        f"| {name} | {item['reported_result']} | {item['comparison_note']} | {item['source']} |"
        for name, item in report["public_benchmarks"].items()
    )
    gap_lines = "\n".join(
        f"| {topic} | {', '.join(info['remaining_external_access'])} |"
        for topic, info in alignment.items()
    )

    return f"""# GO-4 Competitive Benchmark and Solicitation Alignment Report

Generated: {report["generated_at"]}

This report ties the GO-4 enhanced evidence to public solicitation language and
nearby public benchmarks. It is designed to help a proposal writer avoid vague
claims and lift the strongest measured claims into the Phase I narrative.

## Source basis

{source_lines}

## Platform and crypto context

Host: `{platform_info["host_platform"]}` / `{platform_info["host_machine"]}`  
Python: `{platform_info["python_version"]}`

| Primitive | Measured result |
|---|---:|
| HMAC-SHA256 / 136B | {platform_info["hmac_sha256_136b_us"]:.3f} µs |
| AES-256-GCM / 100B | {platform_info["aes_256_gcm_100b_us"]:.3f} µs |
| Ed25519 sign | {platform_info["ed25519_sign_us"]:.3f} µs |
| Ed25519 verify | {platform_info["ed25519_verify_us"]:.3f} µs |
| Full verify-cycle estimate | {platform_info["full_auth_verify_cycle_us"]:.3f} µs |
| Conservative ARM A72 estimate | {platform_info["arm_cortex_a72_estimate_us"]:.3f} µs |
| Reduction vs 15 s current baseline | {platform_info["reduction_vs_15s_current_pct"]:.3f}% |

Note: {platform_info["ssds_class_platform_note"]}

## NV059 — Real-Time Zero Trust

Solicitation fit: reduce authentication from a 15-second current baseline to
under 5 seconds, reduce unauthorized access risk, support degraded operation,
use micro-segmentation, behavioral detection, and immutable audit evidence.

| Metric | Result |
|---|---:|
| Requests | {nv59["total_requests"]:,} |
| Attack vectors | {nv59["attack_vectors_tested"]} |
| Attack block rate | {nv59["attack_block_rate"]:.4f} |
| False allows / false denies | {nv59["false_allows"]} / {nv59["false_denies"]} |
| Decision p95 | {nv59["decision_p95_us"]:.2f} µs |
| Full verify-cycle estimate | {platform_info["full_auth_verify_cycle_us"] / 1000.0:.4f} ms |
| Min DDIL accuracy | {min(nv59["ddil_accuracy"].values()):.4f} |
| Chain verified | {nv59["chain_verified"]} |

KPI gates passed: {sum(alignment["NV059"]["kpis"].values())}/{len(alignment["NV059"]["kpis"])}

## NV061 — Predictive Movement / MTC

Solicitation fit: tracking, forecasting, change detection, hierarchical target
management, scalability, and response-time improvement.

| Metric | Result |
|---|---:|
| IMM RMSE h=3/5/10 | {nv61["imm_rmse_by_horizon_km"]["3"]:.3f} / {nv61["imm_rmse_by_horizon_km"]["5"]:.3f} / {nv61["imm_rmse_by_horizon_km"]["10"]:.3f} km |
| Improvement vs hold, h=5 | {nv61["imm_vs_hold_improvement_h5_pct"]:.1f}% |
| Improvement vs raw velocity, h=5 | {nv61["imm_vs_raw_velocity_improvement_h5_pct"]:.1f}% |
| Conformal coverage / radius | {nv61["conformal_coverage_h5"]:.3f} / {nv61["conformal_radius_h5_km"]:.2f} km |
| Priority recall at threat count | {nv61["priority_recall_at_threat_count"]:.3f} |
| Analyst time reduction model | {nv61["modeled_analyst_time_reduction_pct"]:.1f}% |

KPI gates passed: {sum(alignment["NV061"]["kpis"].values())}/{len(alignment["NV061"]["kpis"])}

## NV063 — Maritime Pattern-of-Life

Solicitation fit: 360-degree air/surface traffic review, no large onboard
historical database, alert content with track number, reason, and confidence,
and SSDS TLR mapping.

| Tier | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|
| Watch | {nv63["watch_tier"]["precision"]:.3f} | {nv63["watch_tier"]["recall"]:.3f} | {nv63["watch_tier"]["f1"]:.3f} | {nv63["watch_tier"]["false_positive_rate"]:.3f} |
| High confidence | {nv63["high_confidence_tier"]["precision"]:.3f} | {nv63["high_confidence_tier"]["recall"]:.3f} | {nv63["high_confidence_tier"]["f1"]:.3f} | {nv63["high_confidence_tier"]["false_positive_rate"]:.3f} |

State efficiency: {nv63["state_bytes_per_track"]} bytes/track; {nv63["processing_us_per_track_update"]:.2f} µs/track-update.

KPI gates passed: {sum(alignment["NV063"]["kpis"].values())}/{len(alignment["NV063"]["kpis"])}

## NV065 — Adaptive Sensor Management

Solicitation fit: initial four-radar SSDS suite, marginal contribution
estimation, release/reallocation recommendations, novel scenario response,
explainability, and worst-case complexity.

| Scenario | Overall improvement | Novel-threat improvement | p99 runtime |
|---|---:|---:|---:|
| Nominal | {nv65["nominal"]["overall_quality_improvement_pct"]:.1f}% | {nv65["nominal"]["novel_threat_quality_improvement_pct"]:.1f}% | {nv65["nominal"]["p99_runtime_us"]:.1f} µs |
| Degraded | {nv65["degraded"]["overall_quality_improvement_pct"]:.1f}% | {nv65["degraded"]["novel_threat_quality_improvement_pct"]:.1f}% | {nv65["degraded"]["p99_runtime_us"]:.1f} µs |
| Burst stress | {nv65["burst_stress"]["overall_quality_improvement_pct"]:.1f}% | {nv65["burst_stress"]["novel_threat_quality_improvement_pct"]:.1f}% | {nv65["burst_stress"]["p99_runtime_us"]:.1f} µs |

KPI gates passed: {sum(alignment["NV065"]["kpis"].values())}/{len(alignment["NV065"]["kpis"])}

## Nearby public benchmarks

These are not exact apples-to-apples comparisons; they define the public
technical neighborhood and help position the proposal honestly.

| Benchmark | Reported public result | Comparison note | Source |
|---|---|---|---|
{benchmark_lines}

## Consolidated external gaps

| Topic | Still requires sponsor/partner access |
|---|---|
{gap_lines}
"""


def build_report() -> dict[str, Any]:
    enhanced = run_all_enhanced()
    platform_info = profile_platform()
    alignment = build_alignment(enhanced, platform_info)
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "official_sources": OFFICIAL_SOURCES,
        "public_benchmarks": PUBLIC_BENCHMARKS,
        "platform": platform_info,
        "enhanced": enhanced,
        "alignment": alignment,
        "boundary": (
            "The comparison is Phase I proposal evidence. It is not target-hardware "
            "WCET, not classified-data validation, and not an operational deployment claim."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", default=str(OUTPUT))
    args = parser.parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    ENHANCED_OUTPUT.mkdir(parents=True, exist_ok=True)
    report = build_report()
    json_path = output_dir / "go4_comparison_report.json"
    md_path = output_dir / "GO4_COMPETITIVE_ALIGNMENT.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    md_path.write_text(render_markdown(report))
    enhanced_json = ENHANCED_OUTPUT / "go4_enhanced_results.json"
    enhanced_md = ENHANCED_OUTPUT / "GO4_ENHANCED_REPORT.md"
    enhanced_json.write_text(json.dumps(report["enhanced"], indent=2, sort_keys=True) + "\n")
    from go4_enhancements import render_enhanced_markdown

    enhanced_md.write_text(render_enhanced_markdown(report["enhanced"]))
    print(f"wrote {json_path.relative_to(ROOT)}")
    print(f"wrote {md_path.relative_to(ROOT)}")
    print(f"wrote {enhanced_json.relative_to(ROOT)}")
    print(f"wrote {enhanced_md.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
