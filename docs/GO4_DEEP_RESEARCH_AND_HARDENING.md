# GO-4 Deep Research and Hardening Notes

Generated: 2026-06-25

This note captures the engineering rationale behind the GO-4 hardening pass for
NV059, NV061, NV063, and NV065. It is intentionally blunt: the goal is to keep
the strongest claims and remove fragile or inflated ones.

## Research readout

The official topic language rewards four things more than broad feature count:

1. **Direct KPI/TLR traceability.** The proposal should show exactly which
   metric answers which solicitation sentence.
2. **Runtime and resource bounds.** These topics care about near-real-time
   behavior, shipboard feasibility, low state, and scaling.
3. **Explainability.** NV061, NV063, and NV065 all benefit when the output
   includes reason codes, confidence, prioritization, or marginal-value logic.
4. **Honest external boundaries.** Phase I evidence can be synthetic, but
   operational truth, SSDS replay, DoD identity, and program-of-record sensor
   parameters remain sponsor-access items.

Primary topic sources:

- NV059: https://www.sbir.gov/topics/12755
- NV061: https://www.sbir.gov/topics/12757
- NV063: https://www.sbir.gov/topics/12759
- NV065: https://www.sbir.gov/topics/12761
- NIST SP 800-207: https://csrc.nist.gov/pubs/sp/800/207/final
- NIST SP 800-207A: https://csrc.nist.gov/pubs/sp/800/207/a/final

Nearby public benchmark context:

- TrAISformer reports strong long-horizon AIS trajectory prediction, below
  about 10 nautical miles up to roughly 10 hours. That is useful context, but
  it is not the same mission as short-horizon MTC prioritization.
- AIS-LLM is a heavier large-model trajectory/anomaly/risk framework. It is a
  useful state-of-art neighbor, but its deployment assumptions differ from the
  compact deterministic surrogate here.
- A recent two-stage maritime anomaly paper reports F1 0.5709 and 9.97% false
  alarm rate for a trained BiLSTM-style approach. The GO-4 high-confidence tier
  is positioned as lower-state, no-large-history, human-verified alerting.

## Hardening changes made

### NV059 — Zero Trust

Problem found: the old hot path signed every event with Ed25519. That made the
experiment slower than necessary and blurred the distinction between policy
decision latency and audit latency.

Fix:

- hash-chain every event;
- sign periodic batch roots every 100 events;
- report policy latency separately from end-to-end decision+audit latency;
- add tamper-rejection proof for the signed batch root.

Result:

- 15,000 hash-chain events;
- 150 signed batch receipts;
- end-to-end decision+audit p99 measured in tens of microseconds on this host;
- 9/9 NV059 alignment gates pass.

### NV061 — Predictive Movement

Problem found: the prior CT-mode maneuver flag was too permissive under noisy
synthetic measurements. It could flag almost everything, which is a classic
overclaim risk.

Fix:

- keep CT mode only as a small forecast-blending component;
- move the reviewer-facing change-detection claim to persistent evidence;
- report precision, recall, false-positive rate, and false-negative rate;
- reduce per-point allocation in the IMM forecast loop.

Result:

- forecast remains 67%+ better than hold at h=5;
- conformal coverage remains near the 90% target;
- change detection is now explicit and falsifiable;
- GO-4 test runtime dropped substantially.

### NV063 — Maritime Pattern-of-Life

Problem found: the two-tier alerting story was strong, but the report did not
include explicit false-negative rate or false-discovery proportion.

Fix:

- add false-negative rate for watch and high-confidence tiers;
- add observed false-discovery proportion;
- keep the two-tier interpretation: watch tier catches more, high-confidence
  tier reduces false alarms.

Result:

- watch tier keeps recall above 0.8 in the current synthetic run;
- high-confidence tier keeps FPR below 1%;
- state remains 176 bytes per track.

### NV065 — Adaptive Sensor Management

Problem found: the scheduler already worked, but it had avoidable per-step set
work and no explicit scaling profile in the GO-4 report.

Fix:

- vectorize marginal-information-value computation;
- precompute conflict lookup;
- avoid rebuilding the novel-threat set inside the loop;
- make conflict-pair report ordering deterministic;
- add scheduler scaling profile at 100, 300, 1,000, and 3,000 tracks.

Result:

- p95 scheduler runtime for 3,000 tracks is under 1 ms on this host in the
  current generated run;
- nominal and degraded novel-threat improvements remain above 90%;
- 8/8 NV065 alignment gates pass.

## Remaining honest risks

These are not code bugs; they are proposal/external-access risks:

- NV059 still needs DoD identity, CAC/PKI, DDS Security, and sponsor-approved
  OT/DDIL policy cases.
- NV061 still needs operational composite tracks and analyst disposition truth.
- NV063 still needs SSDS replay, operator alert disposition, and real hostile
  behavior labels.
- NV065 still needs program-of-record radar parameters and SSDS resource
  manager semantics.

The repo is strongest when those gaps are named as Phase I tasks instead of
hidden.
