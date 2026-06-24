# GO-4 Competitive Benchmark and Solicitation Alignment Report

Generated: 2026-06-24T19:29:33Z

This report ties the GO-4 enhanced evidence to public solicitation language and
nearby public benchmarks. It is designed to help a proposal writer avoid vague
claims and lift the strongest measured claims into the Phase I narrative.

## Source basis

- NV059: https://www.sbir.gov/topics/12755
- NV061: https://www.sbir.gov/topics/12757
- NV063: https://www.sbir.gov/topics/12759
- NV065: https://www.sbir.gov/topics/12761
- Navy FY26 Release 3 index: https://www.navysbir.com/topics26_3.htm
- NIST SP 800-207: https://csrc.nist.gov/pubs/sp/800/207/final
- NIST SP 800-207A: https://csrc.nist.gov/pubs/sp/800/207/a/final

## Platform and crypto context

Host: `macOS-26.1-arm64-arm-64bit` / `arm64`  
Python: `3.9.6`

| Primitive | Measured result |
|---|---:|
| HMAC-SHA256 / 136B | 1.815 µs |
| AES-256-GCM / 100B | 1.430 µs |
| Ed25519 sign | 92.891 µs |
| Ed25519 verify | 200.389 µs |
| Full verify-cycle estimate | 203.635 µs |
| Conservative ARM A72 estimate | 407.269 µs |
| Reduction vs 15 s current baseline | 99.999% |

Note: Representative SSDS COTS single-board computers are commonly x86-class; this host profile is a development proxy, not target WCET evidence.

## NV059 — Real-Time Zero Trust

Solicitation fit: reduce authentication from a 15-second current baseline to
under 5 seconds, reduce unauthorized access risk, support degraded operation,
use micro-segmentation, behavioral detection, and immutable audit evidence.

| Metric | Result |
|---|---:|
| Requests | 15,000 |
| Attack vectors | 10 |
| Attack block rate | 1.0000 |
| False allows / false denies | 0 / 0 |
| Decision p95 | 2.50 µs |
| Full verify-cycle estimate | 0.2036 ms |
| Min DDIL accuracy | 1.0000 |
| Chain verified | True |

KPI gates passed: 8/8

## NV061 — Predictive Movement / MTC

Solicitation fit: tracking, forecasting, change detection, hierarchical target
management, scalability, and response-time improvement.

| Metric | Result |
|---|---:|
| IMM RMSE h=3/5/10 | 1.371 / 1.846 / 3.408 km |
| Improvement vs hold, h=5 | 67.8% |
| Improvement vs raw velocity, h=5 | 67.6% |
| Conformal coverage / radius | 0.893 / 2.62 km |
| Priority recall at threat count | 0.688 |
| Analyst time reduction model | 72.2% |

KPI gates passed: 6/6

## NV063 — Maritime Pattern-of-Life

Solicitation fit: 360-degree air/surface traffic review, no large onboard
historical database, alert content with track number, reason, and confidence,
and SSDS TLR mapping.

| Tier | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|
| Watch | 0.794 | 0.819 | 0.806 | 0.106 |
| High confidence | 0.974 | 0.700 | 0.815 | 0.009 |

State efficiency: 176 bytes/track; 4.05 µs/track-update.

KPI gates passed: 7/7

## NV065 — Adaptive Sensor Management

Solicitation fit: initial four-radar SSDS suite, marginal contribution
estimation, release/reallocation recommendations, novel scenario response,
explainability, and worst-case complexity.

| Scenario | Overall improvement | Novel-threat improvement | p99 runtime |
|---|---:|---:|---:|
| Nominal | 25.8% | 91.2% | 923.2 µs |
| Degraded | 24.0% | 90.1% | 925.7 µs |
| Burst stress | 27.3% | 79.0% | 1331.7 µs |

KPI gates passed: 7/7

## Nearby public benchmarks

These are not exact apples-to-apples comparisons; they define the public
technical neighborhood and help position the proposal honestly.

| Benchmark | Reported public result | Comparison note | Source |
|---|---|---|---|
| TrAISformer | <10 nautical miles up to 10 hours on AIS trajectory prediction | Long-horizon strategic trajectory forecasting; not the same as short-horizon MTC custody and priority triage. | https://arxiv.org/html/2109.03958v4 |
| AIS-LLM | MSE 95.76 in the paper's multi-scale maritime trajectory setup | Large model / trained-corpus approach; useful state of art, but heavier than the deterministic tactical surrogate here. | https://arxiv.org/html/2508.07668v1 |
| Two-stage BiLSTM anomaly detector | F1 0.5709 and 9.97% false alarm rate in a maritime anomaly study | Trained model on a particular data regime; GO-4 high-confidence tier trades recall for much lower synthetic false-positive rate. | https://jurnal.polibatam.ac.id/index.php/JAIC/article/view/11545 |

## Consolidated external gaps

| Topic | Still requires sponsor/partner access |
|---|---|
| NV059 | DoD CAC/PKI integration, DDS Security / combat-network governance, CMMC Level 2 environment and sponsor-approved OT policy cases |
| NV061 | operational composite tracks, identity truth, analyst priority/disposition baselines |
| NV063 | SSDS replay corpus, operator alert dispositions, air/surface hostile behavior labels |
| NV065 | program-of-record radar parameters, SSDS resource manager semantics, operator confirmation workflow |
