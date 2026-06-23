# Phase I to Phase II Deployment Architecture

## Decision

Use a two-plane architecture:

1. **Research and evaluation plane - Python**
   - dataset preparation
   - modeling and simulation
   - ML training and comparison
   - robustness campaigns
   - charts, reports, and requirement traceability

2. **Mission execution plane - native Rust**
   - bounded evidence accumulation
   - custody and priority calculation
   - authenticated binary track messages
   - deterministic sensor scheduling
   - cryptographic enforcement and signed evidence

The native library exposes a C ABI in
`native/assure-kernel/include/assure_kernel.h`. Existing C/C++ systems can link
the library without adopting Rust in the rest of their codebase.

Python must not sit in a hard real-time control loop. It remains acceptable for
offline analytics and for Phase I surrogate demonstrations where the
solicitation explicitly requests modeling, simulation, and feasibility.

## Shared Core, Distinct Products

The seven proposals should not be presented as one generic platform with seven
labels. The shared kernel is an internal engineering advantage. Each proposal
keeps a different mission contract, operator action, failure posture, evidence
meaning, and transition environment.

| Topic | Product identity | Native execution responsibility | Python responsibility |
| --- | --- | --- | --- |
| QSPARX | PQC transition assurance platform | signed inventory events, dependency-safe migration controls | discovery analytics, risk model training, transition simulation |
| NV059 | real-time compartmented zero-trust enforcement | authorization, bounded offline leases, behavior accumulation, receipts | attack generation, policy studies, administration metrics |
| NV061 | custody-aware predictive track hierarchy | association confidence, priority scoring, compact forecasts | model training, maritime scenario generation, baseline analysis |
| NV062 | purpose-bound commercial task broker | task envelope validation, replay control, cryptographic evidence | provider schema adapters, workflow simulation, compliance mapping |
| NV063 | low-history explainable PoL alerting | authenticated track ingestion, sequential anomaly state, alert contract | PoL calibration, model comparison, regional traffic studies |
| NV065 | advisory sensor resource allocator | bounded candidate scheduling, information utility, conflict checks | radar modeling, Monte Carlo scenarios, trade studies |
| NP002 | scalable UAS behavior assurance | track custody, swarm evidence accumulation, signed escalation output | acoustic/EO/RF model training and adversarial scenario generation |

## Native Kernel Guarantees

The initial native kernel implements:

- explicit limits of 64 evidence channels, 64 sensors, and caller-selected
  candidate bounds;
- finite-value, probability, covariance, source, version, and length checks;
- a fixed 136-byte authenticated composite-track frame;
- HMAC-SHA-256 tamper rejection;
- a constant-memory 64-message anti-replay window per authenticated stream;
- deterministic scheduling order;
- sparse spatially gated association without a dense cost matrix;
- release-mode benchmarks and cross-language conformance tests;
- static-library, dynamic-library, Rust-library, and C ABI outputs.

The fixed frame replaces the laboratory JSON/Base64 path for representative
runtime demonstrations. JSON remains suitable for reports and control-plane
APIs where latency is not critical.

## Measured Host Result

The June 22, 2026 ARM64 host measurement is stored at
`results/performance/native_kernel_benchmark.json`.

The current result is approximately:

- evidence update: 0.1 microseconds;
- custody and priority: less than 0.01 microseconds;
- authenticated track decode: approximately 1 microsecond;
- 240-candidate bounded schedule: approximately 3-5 microseconds;
- 1,000-object sparse association: approximately 0.3-0.5 milliseconds;
- release binary: approximately 400 KB on macOS ARM64.

These are host measurements, not target-hardware WCET claims. Phase I should
measure the same binary on representative x86 and ARM hardware and report
p50/p95/p99/max latency, memory, allocation count, CPU load, and thermal
behavior.

## Engineering Performance Gates

These are internal design gates, not solicitation claims.

| Path | Phase I engineering gate |
| --- | ---: |
| Native authorization/evidence decision | p99 below 1 ms excluding external identity providers |
| Authenticated composite-track ingestion | p99 below 100 microseconds per message |
| Custody/priority update | p99 below 100 microseconds per object |
| Four-sensor, 240-candidate advisory schedule | p99 below 1 ms |
| Sparse association of 1,000 well-gated objects | p99 below 10 ms |
| Embedded RTVLAS monitor | p99 below 10 ms on representative target hardware |
| Secure commercial task envelope | p99 below 100 ms excluding provider network latency |

## Transition Work That Cannot Be Solved Locally

The native rewrite does not remove the external evidence gaps:

- AFDW access and authoritative cryptographic inventory for QSPARX;
- Navy combat-network, DoD PKI, and segmentation integration for NV059;
- operational composite tracks and identity truth for NV061;
- credentialed commercial tasking and IL5/IL6 boundary evidence for NV062;
- SSDS interfaces and operator dispositions for NV063;
- program-specific radar parameters and SSDS resource constraints for NV065;
- synchronized real EO/RF/acoustic/radar UAS data for NP002.

Those items should appear as explicit Phase I tasks, government-furnished
information needs, and Phase II transition gates rather than being hidden by
laboratory scores.
