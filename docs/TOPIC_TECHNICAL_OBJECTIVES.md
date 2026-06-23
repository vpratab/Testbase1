# Falsifiable Phase I Technical Objectives

These objectives are engineering drafts for proposal development. Final values
must be reconciled with the solicitation, sponsor feedback, representative
hardware, data availability, and Phase I period of performance.

## QSPARX

**Hypothesis:** dependency-aware cryptographic discovery and migration can
reduce transition breakage while providing measurable PQC readiness.

- Inventory at least 95% of approved-range cryptographic endpoints and
  dependencies in a labeled validation subset.
- Produce zero dependency-order violations on the authoritative test graph.
- Demonstrate rollback and signed checkpoint evidence for every migration wave.
- Measure risk-scoring precision, recall, response time, and analyst workload.
- Failure condition: unresolved dependency cycles, unacceptably disruptive
  migration, or materially incomplete inventory.

## NV059

**Hypothesis:** purpose-bound zero-trust enforcement can reduce access latency,
unauthorized access risk, and administrative burden while remaining functional
under DDIL conditions.

- Authenticate and authorize representative requests below the solicitation's
  five-second requirement.
- Reject all defined unauthorized, revoked, replayed, stale, and
  wrong-compartment cases.
- Demonstrate bounded offline authority without policy widening.
- Measure p50/p95/p99 latency, attack detection, false alarm, availability, and
  administrative actions.
- Failure condition: bypass around the enforcement point, unsafe DDIL behavior,
  or unacceptable false denial.

## NV061

**Hypothesis:** calibrated prediction plus custody-aware hierarchy improves
future-state accuracy and analyst prioritization at increasing track loads.

- Beat hold and raw-velocity baselines on sponsor-approved scenarios.
- Achieve the stated conformal coverage target on held-out tracks.
- Preserve track identity and expose ambiguity under clutter and missed
  detections.
- Process 10,000-object sparse association within a negotiated real-time bound.
- Measure analyst priority recall and decision-time improvement.
- Failure condition: loss of calibration, excessive identity switching, or no
  improvement over existing workflow.

## NV062

**Hypothesis:** purpose-bound, provider-neutral secure tasking can reduce
end-to-end task latency without weakening classification or release controls.

- Complete one credentialed representative provider lifecycle from validated
  task through return-data integrity verification.
- Reject malformed, unauthorized, downgraded, duplicate, stale, and replayed
  transactions.
- Demonstrate algorithm agility without changing the mission transaction
  contract.
- Measure transaction latency separately from provider collection latency.
- Failure condition: ambiguous release authority, schema-specific lock-in, or
  inability to maintain end-to-end evidence.

## NV063

**Hypothesis:** compact, calibrated surface-and-air PoL state can control alert
burden while detecting meaningful deviations without large onboard history.

- Operate with a negotiated compact-state/storage ceiling.
- Demonstrate separate high-confidence and watch alert budgets.
- Measure recall, false-discovery proportion, detection delay, and operator
  dispositions on representative regional replay.
- Maintain authenticated versioned integration messages and reason codes.
- Failure condition: alert fatigue, regional brittleness, unexplained alerts,
  or reliance on impractical historical storage.

## NV065

**Hypothesis:** explainable marginal information value can safely release and
reallocate sensor resources without degrading fire-control-quality tracks.

- Characterize each sensor's marginal contribution under sponsor-provided
  constraints.
- Produce zero invalid schedules and zero missed hard deadlines in the defined
  test envelope.
- Demonstrate bounded p99 recommendation time.
- Compare nominal, degraded, and conservative-fusion scheduling.
- Require operator confirmation during Phase I.
- Failure condition: track-quality loss, constraint violation, unstable
  recommendations, or no benefit over current allocation.

## NP002

**Hypothesis:** low-cost multimodal defensive sensing can improve UAS
detection, tracking, identification, custody, and swarm-behavior awareness
under clutter.

- Evaluate synchronized approved acoustic, EO, RF, and radar inputs where
  available.
- Measure detection, classification, track continuity, identity switching,
  behavior recall, false alarms, latency, memory, and power.
- Preserve uncertainty across correlated sensors.
- Demonstrate bounded execution on representative low-cost hardware.
- Failure condition: modality collapse, excessive clutter false alarms, loss of
  custody at scale, or hardware resource overrun.
