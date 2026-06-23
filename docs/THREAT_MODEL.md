# Cross-Topic Threat Model

## Protected assets

- authorization and tasking decisions;
- track identity, custody, covariance, and priority;
- sensor-allocation recommendations;
- cryptographic inventories and migration state;
- commercial task requests and returned data;
- alert and evidence integrity;
- operator authority and human-confirmation boundaries.

## Trust boundaries

1. Sensor or enterprise data source to adapter.
2. Adapter to authenticated internal message.
3. Research/model plane to bounded native execution plane.
4. Native decision to operator or enforcement point.
5. Government boundary to commercial provider.
6. Local evidence to independent verifier or external anchor.

## Adversary capabilities considered

- malformed, stale, duplicated, reordered, or tampered messages;
- stolen or revoked credentials;
- compromised or misconfigured endpoint;
- behavioral abuse by an authenticated identity;
- sensor spoofing, dropout, clutter, and unknown cross-correlation;
- misleading model confidence under distribution shift;
- dependency-breaking cryptographic migration;
- resource exhaustion through excessive tracks, tasks, or candidates;
- provider schema drift and failed task lifecycle transitions.

## Primary mitigations

| Threat | Mitigation |
| --- | --- |
| Message tampering | authenticate before parse; fixed frame; signed evidence |
| Replay/reordering | bounded per-stream replay window |
| Resource exhaustion | hard channel, sensor, candidate, frame, and edge limits |
| Unknown sensor correlation | covariance intersection |
| Distribution shift | explicit coverage monitoring and rolling recalibration |
| Repeated statistical testing | anytime-valid evidence process |
| Dependency-breaking migration | graph-ordered migration waves and checkpoints |
| Weak custody | confidence penalty and preserved uncertainty |
| Automated unsafe action | advisory posture and mandatory operator confirmation where required |
| Credential abuse | purpose, compartment, resource, action, time, and use-count constraints |

## Residual risks

- Validly authenticated bad data can still be wrong.
- HMAC does not define key distribution or platform authorization.
- Statistical guarantees depend on calibration assumptions.
- Greedy sparse association can be suboptimal in tightly coupled ambiguous
  crossings; it prioritizes bounded execution and requires ambiguity escalation.
- Public data does not reproduce classified sensor phenomenology.
- A compromised enforcement host can bypass software-only decisions.
- Operator overload and automation bias require human-factors evaluation.

## Fail-safe posture by topic

| Topic | Default failure behavior |
| --- | --- |
| QSPARX | stop migration, preserve current state, require review |
| NV059 | deny or use narrowly bounded unexpired offline authority |
| NV061 | preserve custody, increase uncertainty, lower autonomous confidence |
| NV062 | quarantine the transaction and prevent replay |
| NV063 | flag uncertainty; do not label anomaly as hostility |
| NV065 | retain current tasking or issue advisory only |
| NP002 | continue monitoring or cue additional defensive sensing |
