# Tuned Assurance Systems

The shared IP is expressed as two philosophies:

- **AssureEdge Cyber:** constrain sensitive transactions, minimize exposed
  material, bind actions to purpose and policy, and produce independent proof.
- **RTVLAS Mission Assurance:** predict expected state, compare uncertain
  observations, accumulate persistent contradictions, explain decisions, and
  preserve evidence.

The seven systems deliberately do not share the same decision contract.

| Topic | Product family | Action mode | Failure posture | Example decision |
| --- | --- | --- | --- | --- |
| QSPARX | AssureEdge Cyber | migrate | advisory_only | prioritize_crypto_migration |
| NV059 | AssureEdge Cyber | authorize | fail_closed | allow |
| NV062 | AssureEdge Cyber | broker | quarantine_transaction | release_task |
| NP002 | RTVLAS Mission Assurance | escalate | flag_and_continue | activate_protective_measure |
| NV061 | RTVLAS Mission Assurance | prioritize | preserve_custody | rank_high |
| NV063 | RTVLAS Mission Assurance | escalate | flag_and_continue | resolve_identity_and_cue_sensor |
| NV065 | RTVLAS Mission Assurance | advisory | advisory_only | recommend_reallocation |

## Measured philosophy ablations

These checks require the topic-specific philosophy to change an observable
decision. The compiler fails if any expected contrast disappears.

| Topic | Measured distinction |
| --- | --- |
| QSPARX | risk-only ordering breaks the dependency; tuned ordering does not |
| NV059 | persistent low-and-slow evidence changes the authorization outcome |
| NV062 | purpose-bound single-use intent quarantines replay |
| NP002 | formation escalation requires persistence |
| NV061 | uncertain custody reduces confidence and ranking |
| NV063 | a transient deviation and a persistent deviation do not produce the same alert |
| NV065 | resource conflicts can reverse an otherwise attractive recommendation |

## QSPARX

**Mission decision:** Which cryptographic dependencies create the greatest quantum-era mission risk, and what migration order reduces risk without breaking legacy operations?

**PZDR/RTVLAS tuning**

- PZDR minimizes retained secrets while preserving audit evidence
- RTVLAS treats weak cryptographic indicators as accumulated mission risk
- recommendations are evidence-bound rather than opaque scores

**Maintained state**

- cryptographic bill of materials
- dependency graph
- algorithm and key posture
- quantum exposure score
- migration wave state
- compliance evidence lineage

**Evidence proves**

- what cryptographic material was observed
- which risk basis produced the recommendation
- which dependency ordering constrained migration

**Evidence explicitly does not prove**

- proof that an unscanned asset does not exist
- FIPS validation of the chosen implementation

**Current boundary**

- requires enterprise discovery connectors
- does not replace cryptographic module validation

## NV059

**Mission decision:** May this exact subject and device perform this exact action on this combat-data object now, including while disconnected?

**PZDR/RTVLAS tuning**

- PZDR provides minimal-disclosure signed transaction receipts
- RTVLAS contributes persistence against low-and-slow access misuse
- offline authority is explicit and expires rather than becoming implicit trust

**Maintained state**

- signed policy version
- identity and revocation snapshot
- bounded offline trust lease
- per-subject behavioral baseline
- decision receipt chain

**Evidence proves**

- which identity, posture, policy, and behavior caused the decision
- that the decision was not altered after issuance

**Evidence explicitly does not prove**

- proof that the endpoint remains uncompromised after the decision
- network isolation unless an enforcement adapter confirms it

**Current boundary**

- requires real ICAM and segmentation integrations
- local decisions cannot establish remote endpoint integrity

## NV062

**Mission decision:** Can a purpose-bound government collection task cross a commercial boundary confidentially, authentically, quickly, and with replay-safe return evidence?

**PZDR/RTVLAS tuning**

- PZDR turns a sensitive task into a purpose-bound minimal-retention transaction
- RTVLAS treats provider workflow state as an observable sequence with anomaly evidence
- every boundary crossing produces independently verifiable receipts

**Maintained state**

- single-use purpose-bound intent
- provider adapter state
- hybrid classical/PQC session
- replay set
- task and return receipt chain

**Evidence proves**

- the encrypted task matched the authorized purpose
- the provider return corresponds to the same task
- duplicate task use was rejected

**Evidence explicitly does not prove**

- proof of satellite execution without provider evidence
- IL-5 or IL-6 accreditation

**Current boundary**

- requires a real provider API and accreditation path
- cryptographic receipt is not proof of collection

## NP002

**Mission decision:** Do noisy, intermittently observed UAS tracks collectively exhibit a persistent formation behavior consistent with escalating threat?

**PZDR/RTVLAS tuning**

- RTVLAS elevates formation behavior only after persistent contradictions
- custody uncertainty lowers confidence instead of disappearing
- PZDR evidence enables compact, tamper-evident post-event review

**Maintained state**

- multi-target custody hypotheses
- swarm centroid and spread
- formation coherence and contraction
- member orientation and acceleration
- persistent intent evidence

**Evidence proves**

- which track geometry and persistence caused escalation
- how missed detections and custody uncertainty affected confidence

**Evidence explicitly does not prove**

- UAS payload identity without a classifier
- authority to neutralize a target

**Current boundary**

- requires a real detection and identification front end
- behavior inference is not target identity

## NV061

**Mission decision:** Where will each object probably be, how sure are we that it is the same object, and which uncertain forecast deserves analyst attention?

**PZDR/RTVLAS tuning**

- RTVLAS supplies prediction, covariance, persistence, and explicit uncertainty
- weak custody reduces priority confidence instead of being hidden
- PZDR receipts preserve why analysts were directed to one object

**Maintained state**

- object state and covariance
- multi-source custody confidence
- future-state forecast distribution
- behavior-change evidence
- priority history and analyst disposition

**Evidence proves**

- which forecast, uncertainty, behavior, and custody produced ranking
- whether priority changed due to risk or reduced confidence

**Evidence explicitly does not prove**

- perfect identity across unobserved intervals
- intent inferred solely from kinematics

**Current boundary**

- requires broader sensor and identity data
- kinematic forecast is not a complete adversary intent model

## NV063

**Mission decision:** Is this local air or surface contact persistently out of family for the current operating context despite limited historical storage?

**PZDR/RTVLAS tuning**

- RTVLAS online calibration learns local normal without a global archive
- persistent evidence separates temporary maneuver from sustained deviation
- PZDR receipts make machine reasoning reviewable without retaining all raw traffic

**Maintained state**

- compact per-track motion model
- compressed route primitives
- persistent speed, heading, closing, and identity residuals
- watch and high-confidence alert state

**Evidence proves**

- which local baseline and persistent deviation caused the alert
- which data-quality screen was applied

**Evidence explicitly does not prove**

- malicious intent from anomaly alone
- global completeness of the local Pattern of Life

**Current boundary**

- anomaly does not establish hostility
- requires ADS-B and SSDS composite-track evaluation

## NV065

**Mission decision:** Which sensor task contributes the least additional track information, and where would that finite resource create greater mission value?

**PZDR/RTVLAS tuning**

- RTVLAS covariance becomes marginal evidence value rather than a trust score
- persistent priority changes prevent task thrashing
- PZDR receipts preserve exactly why scarce sensor time was moved

**Maintained state**

- sensor-track contribution matrix
- diminishing-return state
- resource conflicts
- candidate task utility
- recommendation history and operator disposition

**Evidence proves**

- the estimated marginal track-quality contribution
- why the alternative task had greater weighted mission value

**Evidence explicitly does not prove**

- actual radar performance beyond the supplied model
- authority to retask sensors automatically

**Current boundary**

- requires traceable program-of-record sensor models
- Phase I recommendations remain advisory
