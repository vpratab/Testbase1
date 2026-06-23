# Topic Proposal Packets

These packets are the proposal-writer view of the evidence base. They
separate what can be claimed in Phase I from what still requires
sponsor data, credentials, or partners.

## NV059 — GO (88/100)

**Need:** Control who and what can access combat-system data in real time, even under degraded connectivity.

**Hypothesis:** Purpose-bound zero-trust enforcement can keep compartmented data usable while rejecting stale, replayed, revoked, and wrong-purpose access.

**Proposal claim:** We will demonstrate a combat-system zero-trust access layer with bounded native decisions, protocol adapters, DDIL leases, and signed evidence receipts.

**Strongest evidence:**

- secure OPC UA and Cyclone DDS authorization tests
- mTLS microsegmentation and Modbus/TCP surrogate paths
- native microsecond-scale decision primitives
- replay, revocation, compartment, and DDIL negative tests

**Primary artifacts:**

- `results/trl4_wave4/wave4_campaign_results.json`
- `results/trl4_wave5/wave5_campaign_results.json`
- `results/independent_benchmark/INDEPENDENT_BENCHMARK.md`

**First-month proof:** Freeze the identity, compartment, protocol, DDIL, and latency test matrix with sponsor-approved policy cases.

**Base demo:** Run the enforcement point against representative authorized and unauthorized transactions and report latency, availability, false denial, replay rejection, and audit evidence.

**Option demo:** Integrate sponsor-provided identities or a sponsor-approved identity surrogate and exercise a larger combat-network emulation.

**Failure condition:** Bypass around the enforcement point, unsafe DDIL policy widening, or unacceptable false denial.

**Do not overclaim:** The lab is not an accredited combat network and does not prove production DoD identity integration.

**External access request:** test identities, compartment/purpose matrix, representative policy decisions, two or more network segments, and protocol endpoints

## NV061 — GO (88/100)

**Need:** Track many maritime objects, predict future movement, preserve identity, and prioritize what analysts should look at first.

**Hypothesis:** Calibrated forecasting plus custody-aware priority can reduce analyst load while preserving uncertainty and identity ambiguity.

**Proposal claim:** We will demonstrate future-state prediction, custody-aware hierarchy, dense-crossing identity stress, and cross-region public-data transfer evidence.

**Strongest evidence:**

- frozen Puget-to-New-York forecast transfer improved over hold by 20.8%
- custody-aware dense crossing improved 256-object accuracy from 57.4% to 85.2%
- identity switches dropped 56.8% in the dense-crossing campaign
- native sparse association and authenticated track frame benchmarks

**Primary artifacts:**

- `results/frozen_region/frozen_region_results.json`
- `results/dense_crossing/dense_crossing_results.json`
- `results/trl4_wave5/EVIDENCE_INDEX.md`

**First-month proof:** Freeze track, custody, forecast, priority, analyst-time, and scale metrics with any sponsor-provided composite-track examples.

**Base demo:** Evaluate prediction and priority on public plus sponsor-approved tracks, including failure cases for identity ambiguity and missed detections.

**Option demo:** Run on de-identified composite tracks with analyst priority dispositions if available.

**Failure condition:** Loss of calibration, excessive identity switching, or no improvement over analyst workflow or baseline forecasting.

**Do not overclaim:** Public AIS/ADS-B identifiers are not operational intent truth or Navy analyst-priority truth.

**External access request:** de-identified multi-source tracks with covariance, source, identity continuity events, and analyst priority dispositions

## NV065 — GO (85/100)

**Need:** Help ship operators decide which sensors should spend limited time on which tasks without degrading important track quality.

**Hypothesis:** Explainable marginal information value can recommend resource release and retasking while respecting hard SSDS-like constraints.

**Proposal claim:** We will deliver an operator-advisory scheduler that explains each recommendation, enforces hard task constraints, and measures track-quality utility.

**Strongest evidence:**

- zero invalid schedules in surrogate campaigns
- bounded native scheduler timing
- beam, dwell, slew, revisit, and operator-advisory contracts
- conservative fusion and degradation studies

**Primary artifacts:**

- `results/trl4_wave5/wave5_campaign_results.json`
- `results/performance/native_kernel_scaling.json`
- `docs/TOPIC_TECHNICAL_OBJECTIVES.md`

**First-month proof:** Translate provided sensor/task parameters into hard constraints, deadlines, conflicts, and track-quality utility definitions.

**Base demo:** Run advisory scheduling on sponsor-approved scenarios and compare nominal, degraded, and conservative-fusion schedules.

**Option demo:** Profile timing on representative hardware or a sponsor-approved SSDS-like replay harness.

**Failure condition:** Track-quality loss, constraint violation, unstable recommendations, missed hard deadlines, or no benefit over current allocation.

**Do not overclaim:** Generic radar and sensor parameters are not SSDS validation or fire-control-quality proof.

**External access request:** reference combat-system architecture, sensor task parameters, hard conflicts, deadline semantics, and track-quality definitions

## NV063 — GO (83/100)

**Need:** Notice unusual ship or aircraft behavior in crowded maritime areas without exhausting watchstanders.

**Hypothesis:** Compact pattern-of-life state plus watch/high-confidence alert tiers can control burden while flagging meaningful deviations.

**Proposal claim:** We will demonstrate a low-history, explainable alerting method with frozen regional transfer testing and explicit failed single-tier diagnostics.

**Strongest evidence:**

- frozen Puget-to-New-York transfer preserved a usable watch-tier contract
- single-tier alert targets failed and remain recorded
- high-confidence nominal-proxy alert rate was zero in the New York sample
- authenticated composite interface and reason-code evidence

**Primary artifacts:**

- `results/frozen_region/frozen_region_results.json`
- `results/frozen_region/FROZEN_REGION_REPORT.md`
- `docs/DATA_AND_MODEL_CARDS.md`

**First-month proof:** Freeze regional replay, compact-state ceiling, watch budget, high-confidence budget, and operator-disposition protocol.

**Base demo:** Run regional replay with reason-coded watch and high-confidence tiers, measuring recall, alert burden, delay, and storage.

**Option demo:** Collect operator dispositions on replayed alerts and tune thresholds only under a documented calibration protocol.

**Failure condition:** Alert fatigue, regional brittleness, unexplained alerts, or reliance on impractical historical storage.

**Do not overclaim:** Injected anomalies and nominal proxies are not hostile-behavior labels or operational false-alarm estimates.

**External access request:** representative regional replay, interface schema, storage ceiling, and operator watch/high-confidence dispositions

## NV062 — CONDITIONAL GO (82/100)

**Need:** Let government users securely task commercial assets without exposing intent or losing approval, cancellation, return, and retention evidence.

**Hypothesis:** A provider-neutral secure task envelope can preserve purpose, release authority, replay protection, and return-data integrity across commercial interfaces.

**Proposal claim:** We will demonstrate provider-neutral secure tasking against public provider schemas, sandbox paths, lifecycle states, and verified returns.

**Strongest evidence:**

- Capella live OpenAPI reachability
- Umbra production and sandbox tasking endpoint schema conformance
- real Capella and Umbra open-data return verification
- hybrid task envelopes with replay, tamper, and authorization negative tests

**Primary artifacts:**

- `results/trl4_wave5/wave5_campaign_results.json`
- `results/trl4_wave4/wave4_campaign_results.json`
- `docs/EXTERNAL_ACCESS_PACKAGES.md`

**First-month proof:** Establish provider interface, credential boundary, approval chain, cancellation, return, and retention semantics.

**Base demo:** Exercise public schemas and simulated sandbox lifecycle with valid and invalid task transactions, return verification, and signed evidence.

**Option demo:** Complete one credentialed sandbox lifecycle if provider or government boundary approval is available.

**Failure condition:** Ambiguous release authority, schema-specific lock-in, inability to maintain end-to-end evidence, or no credible provider sandbox path.

**Do not overclaim:** No live paid collection, IL5/IL6 authorization, or classified tasking authority has been demonstrated.

**External access request:** sandbox credential guidance, representative task and lifecycle schemas, approval/cancellation states, and return metadata

## QSPARX — CONDITIONAL GO (81/100)

**Need:** Find vulnerable cryptography, map dependencies, and plan a safe post-quantum migration without breaking mission systems.

**Hypothesis:** Dependency-aware cryptographic discovery and staged migration can reduce transition breakage while producing measurable PQC readiness.

**Proposal claim:** We will demonstrate cryptographic inventory, dependency-safe migration sequencing, rollback checkpoints, and real PQC operations in a sponsor-approved range.

**Strongest evidence:**

- ML-KEM and ML-DSA operations
- certificate, PKCS#12, OpenSSH, source, and configuration discovery
- dependency-safe migration execution
- synthetic 200-asset migration study avoiding break-before-dependency errors

**Primary artifacts:**

- `results/trl4_wave5/wave5_campaign_results.json`
- `results/theory_campaign/theory_campaign_results.json`
- `docs/EXTERNAL_ACCESS_PACKAGES.md`

**First-month proof:** Establish authorized inventory scope, ground-truth subset, dependency graph, and rollback exercise.

**Base demo:** Inventory a sanitized range, score PQC readiness, build dependency waves, and prove rollback evidence on a representative subset.

**Option demo:** Exercise legacy interoperability and mission-continuity checks on a sponsor-approved AFDW-like replica.

**Failure condition:** Materially incomplete inventory, unresolved dependency cycles, disruptive migration, or no measurable readiness improvement.

**Do not overclaim:** The local enterprise range is not AFDW inventory and is not FIPS-validated cryptographic module operation.

**External access request:** sanitized asset inventory, cryptographic metadata, dependency edges, key-storage class, and approved migration policy

## NP002 — PARTNER GO (77/100)

**Need:** Improve defensive detection, identification, tracking, and handoff for small hostile UAS without claiming full defeat authority.

**Hypothesis:** Low-cost multimodal sensing and custody-aware tracking can improve UAS track continuity, identification, and handoff under clutter.

**Proposal claim:** We will demonstrate a defensive sensing, track-custody, identification, and handoff module for an existing C-UAS architecture.

**Strongest evidence:**

- NASA UAS acoustic recording-level holdouts
- typed tracking and behavior evidence
- custody-aware dense-crossing improvement
- bounded native tracking primitives and handoff-contract plan

**Primary artifacts:**

- `results/dense_crossing/dense_crossing_results.json`
- `results/trl4_wave4/wave4_campaign_results.json`
- `docs/NP002_FIELD_VALIDATION_PATH.md`

**First-month proof:** Freeze the selected technology lane, target groups, modalities, clutter conditions, field truth, and integration boundary.

**Base demo:** Replay synchronized or sponsor-approved sensor data and measure detection, classification, track continuity, identity switches, and latency.

**Option demo:** Support controlled field collection or demonstrate non-authoritative handoff to an existing defensive C-UAS system.

**Failure condition:** Modality collapse, excessive clutter false alarms, loss of custody at scale, hardware resource overrun, or no integration owner.

**Do not overclaim:** The current work is not a full Detect-Track-Identify-Assess-Neutralize chain and does not control defeat effects.

**External access request:** synchronized radar/EO/IR/RF/acoustic/Remote ID recordings, target truth, clutter/weather metadata, and handoff timestamps
