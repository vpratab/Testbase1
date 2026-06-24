# GO-4 Enhanced Evidence Report

Generated: 2026-06-24T19:29:22Z

These results extend the base feasibility experiments with additional rigor for
the four highest-readiness topics. All results remain synthetic surrogates;
external integration gaps are documented per topic.

## NV059 — Zero-Trust DDIL Authorization

| Metric | Result |
|---|---:|
| Total requests | 15,000 |
| Attack vectors tested | 10 |
| Attacks blocked | 7,500 |
| Attack block rate | 1.0000 |
| False allows | 0 |
| False denies | 0 |
| Behavioral detections | 750 |
| Decision p50 / p95 / p99 (µs) | 1.96 / 2.50 / 5.62 |
| Chain verified | True |
| DDIL accuracy — connected | 1.0000 |
| DDIL accuracy — degraded | 1.0000 |
| DDIL accuracy — disconnected | 1.0000 |
| Compartments enforced | CUI, SECRET-REL |
| Bounded offline lease tested | True |

**Limit:** Python policy surrogate. Real CAC/PKI, DDS Security governance, and combat-network segmentation remain Phase I integration work.

## NV061 — Predictive Movement (IMM + Conformal)

| Metric | Result |
|---|---:|
| IMM RMSE horizon-3 / 5 / 10 (km) | 1.3707 / 1.8458 / 3.4078 |
| IMM vs Kalman improvement (h=5) | -1.5% |
| IMM vs hold improvement (h=5) | 67.8% |
| Conformal coverage h=5 (target 90%) | 0.893 |
| Conformal radius h=5 (km) | 2.62 |
| Maneuver detection rate (CT mode) | 1.000 |
| Priority recall at threat count | 0.688 |
| Mean custody confidence | 0.840 |
| Critical + High tier tracks | 44 |
| Modeled analyst time reduction | 72.2% |

**Limit:** IMM uses low-order constant-velocity/constant-turn modes on synthetic tracks. Operational composite tracks and analyst disposition truth remain Phase I access work.

## NV063 — Maritime Pattern-of-Life (Two-Tier)

| Metric | Watch tier | High-confidence tier |
|---|---:|---:|
| Precision | 0.7939 | 0.9739 |
| Recall | 0.8187 | 0.7000 |
| F1 | 0.8062 | 0.8145 |
| False positive rate | 0.1062 | 0.0094 |
| Total alerts | 165 | 115 |

State: 176 bytes/track → 171.9 KB for 1,000 tracks.  
Processing: 4.05 µs/track-update.

**Limit:** Two-tier thresholds calibrated on synthetic nominal tracks. Injected anomalies are controlled deviations, not labeled operational hostile behavior.

## NV065 — Adaptive Sensor Management

| Scenario | Overall improvement | Novel-threat improvement | p95 runtime |
|---|---:|---:|---:|
| Nominal | 25.8% | 91.2% | 911.8 µs |
| Degraded (MK-9 fails 40%) | 24.0% | 90.1% | 912.7 µs |
| Burst stress (300 tracks, 50 novel) | 27.3% | 79.0% | 1317.6 µs |

Conflict pairs enforced: 2.  
Worst-case complexity: `O(k × n log n) per scheduling step`.

**Limit:** Sensor variances are open low-fidelity surrogates, not program-of-record radar parameters. The output is advisory and requires operator/SSDS confirmation.
