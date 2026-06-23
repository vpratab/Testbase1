# Current Capability and Phase I Potential

Assessment date: June 23, 2026

## Executive conclusion

The project is now a strong pre-proposal technical evidence base. It is not yet
seven government-ready systems.

The most credible current advantages are:

- one reusable assurance architecture with distinct mission contracts;
- bounded native execution and C/C++ integration;
- authenticated, replay-safe, independently verified interfaces;
- calibrated uncertainty and false-alert semantics;
- conservative fusion when sensor correlation is unknown;
- dependency-safe cryptographic migration;
- unusually explicit limitations and reproducible evidence.

The largest remaining weaknesses are:

- sponsor-specific data and interfaces;
- representative target hardware;
- independent operator and SME evaluation;
- real anomaly, threat, identity, payload, and disposition truth;
- proposal personnel, commercialization, and transition evidence.

Navy guidance states that technical merit is the most important evaluation
criterion, followed by qualifications of key personnel and commercialization
potential with equal importance. Therefore, additional code can strengthen only
one part of the award decision.

## Current benchmark findings

The independent harness built the release executable once, discarded one
warm-up process, and then ran:

- 20 independent benchmark processes at 150,000 iterations each;
- 15 independent scaling processes;
- 20 independent conformance processes;
- executable and source-tree hashing;
- raw-observation retention.

Measured locally in release mode on macOS ARM64:

| Path | Repeated-campaign result |
| --- | ---: |
| Authenticated 136-byte track decode | about 1 microsecond median |
| 240-candidate sensor schedule | about 3-4 microseconds median |
| 1,000-object sparse association | about 0.35-0.40 milliseconds median |
| 10,000-object sparse association | about 4-7 milliseconds in the declared repeated runs |
| 3,840-candidate schedule | about 0.22 milliseconds median; a shared-host process reached 1.09 milliseconds |
| Native executable | 441.2 KiB |

All 20 conformance processes produced equivalent results. The executable
SHA-256 was
`27fe1adcd9d14a44618e6e1b7372c559c92342505a7f14a128767b77d7f32ad8`.
The table summarizes the repeated campaigns run during this assessment. The
latest complete raw observations and method are in
`results/independent_benchmark`.

An uncontrolled ad hoc run before the repeated protocol measured 7.43
milliseconds for the 10,000-object case. It is not included in the formal
sample because it preceded the declared warm-up and run protocol, but it is
reported here to avoid hiding host variability.

These results establish that the selected algorithms are not intrinsically too
slow for Phase I. They do not establish:

- target-hardware worst-case execution time;
- deterministic scheduling under combat-system load;
- end-to-end network and sensor latency;
- performance in dense ambiguous geometry;
- hardware power and thermal behavior.

The 10,000-object association benchmark uses favorable spatial separation and
gating. The current greedy sparse assignment prioritizes bounded execution; it
does not replace a PMBM, GLMB, JPDA, or full multiple-hypothesis tracker in
ambiguous high-density crossings.

## Online research findings that materially change positioning

### Solicitation status

The Navy FY26 Release 3 topics were pre-released June 3, 2026, open June 24,
2026, and close July 22, 2026 at 12:00 p.m. Eastern. The official Navy index
lists NV059, NV061, NV062, NV063, NV065, and NP002.

The live topic pages reduce the Phase I question to the following:

| Topic | What Phase I actually has to establish |
| --- | --- |
| QSPARX | AFDW cryptographic inventory, key/storage/legacy mapping, measurable AI/ML performance, and a simulated Air Force prototype |
| NV059 | A NIST-aligned compartmented-data concept, detailed architecture and data flow, and modeling/simulation against Navy performance goals |
| NV061 | Identification, tracking, prioritization, forecast and change-detection feasibility, increasing data load, response-time improvement over manual work, and hierarchical target management |
| NV062 | Secure architecture and protocols, integration with existing commercial tasking interfaces, and simulated secure government-to-commercial exchange |
| NV063 | An explainable automated pattern-of-life method shown feasible through modeling, simulation, or other evidence |
| NV065 | Explainable, operator-advisory SSDS sensor allocation that preserves relevant track quality while identifying higher-value tasking |
| NP002 | The existing technology, DON system to improve, required modifications, expected improvement, and impact on recognition, detection, tracking, and low-cost non-kinetic defeat of Group 2-and-below UAS |

NP002 is not a one-month Phase I. Its official page specifies a six-month Base
period capped at $200,000 and a six-month Option capped at $115,000.

### QSPARX

The official topic begins at TRL 3 and asks Phase I to inventory AFDW
cryptographic assets, map key management/storage/legacy interoperability, set
AI/ML accuracy and response metrics, and demonstrate a prototype in a simulated
Air Force environment.

NIST finalized its crypto-agility guidance on December 19, 2025 and continues
to publish PQC transition material. Therefore, inventory plus PQC algorithms is
not differentiating by itself. The strongest differentiation is:

- executable dependency-safe migration;
- mission-continuity and rollback checkpoints;
- signed evidence;
- hybrid transition without breaking legacy dependencies;
- measurable disruption and interoperability risk.

### NV059

NIST zero trust is a set of principles and architecture patterns, not a single
product. Existing standards already cover policy engines, enforcement points,
identity, resources, and cloud-native access control.

The project must differentiate through:

- combat/DDIL operation;
- purpose and compartment semantics;
- heterogeneous protocol enforcement;
- bounded native latency;
- behavior monitoring with controlled false alarms;
- evidence suitable for assessment.

### NV061 and NV063

Transformer trajectory prediction, AIS anomaly detection, random-finite-set
tracking, and PMBM/GLMB methods are established. Recent PMBM work explicitly
handles birth, death, clutter, and unknown target counts; clustered approaches
have been evaluated beyond one thousand targets.

The present project is lighter and faster but less sophisticated in ambiguous
multi-target Bayesian inference. Its credible advantage is:

- custody-aware prioritization;
- conservative cross-source fusion;
- conformal regions;
- false-discovery-controlled alert tiers;
- compact state;
- explainability and bounded execution.

### NV062

Capella currently advertises:

- automated scheduling every 20 minutes;
- REST tasking and delivery APIs;
- STAC metadata;
- AWS GovCloud FedRAMP High;
- encryption through uplink, downlink, processing, and storage;
- automated task status and delivery.

Therefore, secure automation itself is not novel. The proposal must focus on
government-owned cross-provider control:

- purpose-bound authority;
- classification and release policy;
- provider-independent transaction semantics;
- replay, cancellation, return, retention, and approval evidence;
- cryptographic agility;
- cross-domain integration.

### NV065

Information-driven sensor selection, POMDPs, random-finite-set sensor control,
and robust/submodular scheduling are established fields. The current scheduler
is a fast feasibility implementation, not new radar mathematics.

Its defensible value is:

- direct mapping to the four named radar roles;
- explainable marginal fire-control-track contribution;
- hard task constraints;
- conservative fusion;
- operator advisory posture;
- a native integration path.

### NP002

Current C-UAS research and government acquisition guidance emphasize
detection, tracking, identification, modality tradeoffs, false alarms,
environmental conditions, and integrated sensor fusion. Recent research
continues to emphasize RGB/IR, radar, RF, and acoustic fusion.

The NASA acoustic dataset is real and useful, but its public page does not
specify a license and it does not provide synchronized radar/EO/RF/payload
truth. The present system supports a defensive sensing and behavior lane, not
complete C-UAS coverage.

## Topic assessment

Scores below are independent technical-readiness judgments, not award
probabilities and not the internal requirement-coverage scores.

| Topic | Current technical position | Phase I potential with access | Main reason |
| --- | ---: | ---: | --- |
| NV059 | 88/100 | 95/100 | Strong enforcement architecture and timing; needs DoD identity and representative combat network |
| NV061 | 86/100 | 94/100 | Strong uncertainty/custody/scale story; needs operational composite truth and analyst baseline |
| NV065 | 85/100 | 94/100 | Excellent solicitation fit and bounded scheduler; generic radar parameters remain decisive |
| NV063 | 83/100 | 93/100 | Strong compact/calibrated alert architecture; anomaly and operator truth remain synthetic or absent |
| QSPARX | 81/100 | 93/100 | Strong crypto-agility execution; solicitation explicitly asks for AFDW inventory |
| NV062 | 79/100 | 92/100 | Strong assurance layer, but incumbent providers already automate secure tasking |
| NP002 | 75/100 | 91/100 | Good low-cost runtime and behavior evidence; missing synchronized multimodal field truth |

## Topic-by-topic current proof and missing proof

### NV059

**Proven now**

- native microsecond-scale decision primitives;
- secure OPC UA, DDS, Modbus/TCP, and mTLS surrogate paths;
- replay, revoked credential, compartment, and DDIL tests;
- signed evidence and anytime-monitor experiment.

**Not proven**

- combat-network bypass resistance;
- DoD PKI/CAC integration;
- actual administrative-overhead reduction;
- representative operator false-denial rate.

### NV061

**Proven now**

- real public AIS/OpenSky ingestion;
- forecast baselines;
- 90%-target conformal coverage with 92.9% measured held-out coverage;
- unknown-correlation fusion improvement;
- 10,000-object favorable-geometry association under 6 ms.

**Not proven**

- dense-clutter identity continuity;
- operational identity and intent;
- improvement versus Navy analyst workflow;
- PMBM/GLMB-class ambiguity performance.

### NV065

**Proven now**

- hard scheduling constraints;
- zero invalid schedules in current surrogate campaign;
- fast scaling;
- explainable information utility;
- conservative fusion and operator confirmation.

**Not proven**

- actual sensor contribution to fire-control-quality tracks;
- SSDS resource conflict semantics;
- benefit using program radar parameters;
- robust advantage under measured failure distributions.

The robust-scheduling experiment currently shows only a small lower-tail
improvement. That is a framework result, not a major performance claim.

### NV063

**Proven now**

- public real surface/air trajectories;
- authenticated composite interface;
- compact state;
- grouped-track validation;
- high-confidence and watch alert tiers;
- causal adaptation under synthetic distribution shift.

**Not proven**

- real malicious or threatening anomaly labels;
- operator alert utility;
- regional generalization across independent dates and oceans;
- SSDS display and workflow integration.

### QSPARX

**Proven now**

- real ML-KEM and ML-DSA operations;
- certificate, PKCS#12, OpenSSH, source/configuration discovery;
- dependency-safe migration;
- 91 avoided break-before-dependency errors in a synthetic 200-asset study.

**Not proven**

- AFDW inventory coverage;
- mission-system migration disruption;
- FIPS-validated cryptographic module operation;
- live rollback and interoperability in an Air Force environment.

### NV062

**Proven now**

- hybrid task envelopes;
- replay and tamper rejection;
- provider schema and lifecycle modeling;
- return-data verification;
- cross-language authenticated interface.

**Not proven**

- one credentialed collection lifecycle;
- IL5/IL6 or classified release authorization;
- integration advantage over existing provider security;
- actual reduction in order-to-delivery time.

### NP002

**Proven now**

- real NASA acoustic data;
- recording-level holdouts;
- low-cost native tracking and behavior logic;
- scalable sparse association;
- conservative fusion primitives.

**Not proven**

- drone versus bird/vehicle discrimination across environments;
- synchronized EO/RF/radar/acoustic fusion;
- payload identification;
- weather, multipath, urban clutter, and field false alarms;
- full Detect-Track-Identify-Assess-Neutralize coverage.

## Proposal competitiveness

The code is now sufficient to support a technically serious Phase I proposal.
It is not sufficient to make all seven proposals equally strong.

Best current submission order:

1. NV059
2. NV061
3. NV065
4. NV063
5. QSPARX
6. NV062
7. NP002

The practical award bottleneck is likely to move from code toward:

- topic-specific key personnel;
- letters or credible paths to sponsor/provider data;
- commercialization and transition partners;
- proposal clarity;
- government need and platform fit;
- compliance and eligibility.

## Highest-value next experiments

1. **Independent date/region AIS test:** acquire a second NOAA AIS day and
   geographically separate region; freeze all thresholds before evaluation.
2. **Dense crossing benchmark:** compare sparse greedy association against
   Hungarian assignment and a tractable PMBM/JPDA baseline; report accuracy,
   identity switches, edges, memory, and latency.
3. **Linux x86 and ARM hardware matrix:** report cold start, p50/p95/p99/max,
   CPU, memory, and power where available.
4. **Credentialed provider sandbox:** complete one actual NV062 task lifecycle.
5. **Real identity environment:** connect NV059 to sponsor-approved PKI and
   policy enforcement.
6. **Operator study:** measure alert dispositions, priority utility, and time
   saved for NV061/NV063/NV065.
7. **Multimodal C-UAS collection or partnership:** obtain synchronized,
   redistributable field data.

## Primary sources

- [Navy FY26 Release 3 topic index](https://www.navysbir.com/topics26_3.htm)
- [NV059 official topic](https://www.navysbir.com/n26_3/DON26BZ03-NV059.htm)
- [NV061 official topic](https://www.navysbir.com/n26_3/DON26BZ03-NV061.htm)
- [NV062 official topic](https://www.navysbir.com/n26_3/DON26BZ03-NV062.htm)
- [NV063 official topic](https://www.navysbir.com/n26_3/DON26BZ03-NV063.htm)
- [NV065 official topic](https://www.navysbir.com/n26_3/DON26BZ03-NV065.htm)
- [NP002 official topic](https://www.navysbir.com/n26_3/DON26BX03-NP002.htm)
- [QSPARX official topic](https://www.sbir.gov/topics/12764)
- [Navy SBIR evaluation guidance](https://navysbir.com/training-oh/DON-Office-Hours-4-30-25.pdf)
- [NIST PQC publications](https://csrc.nist.gov/Projects/post-quantum-cryptography/publications)
- [NIST SP 800-207A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207A.pdf)
- [NIST SP 800-218 SSDF](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-218.pdf)
- [Capella automated tasking](https://www.capellaspace.com/solution/automated-tasking)
- [NASA Small UAS acoustics](https://data.nasa.gov/dataset/small-uas-flyover-acoustics-data)
- [PMBM filter derivation](https://arxiv.org/pdf/1703.04264)
- [Clustered PMBM beyond one thousand targets](https://arxiv.org/pdf/2205.14021)
- [Cell-MB sensor control](https://arxiv.org/pdf/2108.11236)
- [Multi-sensor UAV classification](https://arxiv.org/pdf/2410.16089)
