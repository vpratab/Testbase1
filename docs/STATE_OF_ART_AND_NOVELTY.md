# State of the Art and Defensible Novelty

## Positioning rule

The proposals should not claim that their individual primitives are new.
Zero-trust architecture, PQC discovery, transformer trajectory forecasting,
covariance intersection, conformal prediction, random-finite-set tracking,
information-driven sensor scheduling, and DDS security all have established
literatures or standards.

The defensible innovation is the combination of:

- bounded native mission execution;
- empirically calibrated uncertainty;
- explicit custody and unknown-correlation handling;
- purpose-bound authority and replay-safe transactions;
- dependency-aware migration and rollback evidence;
- explainable advisory actions;
- signed, independently reproducible evidence.

## QSPARX

### Established baseline

- [NIST CSWP 39 - Considerations for Achieving Cryptographic Agility](https://csrc.nist.gov/pubs/cswp/39/considerations-for-achieving-cryptographic-agility/final)
- [NIST NCCoE Migration to Post-Quantum Cryptography](https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc)
- [NIST CSWP 48 - Mapping PQC Migration Capabilities](https://csrc.nist.gov/pubs/cswp/48/mapping-migration-to-pqc-project-capabilities-to-r/ipd)

Inventory and algorithm replacement are therefore not sufficient novelty.

### Defensible delta

- Build a dependency graph from certificates, keys, protocols, applications,
  hardware roots, and mission services.
- Generate migration waves that cannot migrate a dependent before its
  cryptographic foundation.
- Record interoperability checkpoints, rollback state, mission risk, and
  signed evidence for every migration action.
- Use anytime-valid monitoring to detect unexpected failure rates during
  migration without repeatedly resetting a fixed-window alarm.

The current 200-asset simulation produced 91 dependency violations from naive
risk ordering and zero from dependency-safe ordering.

## NV059 - Real-Time Zero Trust

### Established baseline

- [NIST SP 800-207 - Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
- [NIST SP 800-207A - Cloud-Native Access Control](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207A.pdf)
- [NIST SP 1800-35 - Implementing a Zero Trust Architecture](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.1800-35.pdf)
- [OMG DDS Security 1.2](https://www.omg.org/spec/DDS-SECURITY/1.2/About-DDS-SECURITY)

### Defensible delta

- Purpose- and compartment-bound authorization rather than network-location
  trust.
- Expiring DDIL trust leases that fail closed without silently expanding
  authority.
- Native enforcement across Modbus/TCP, OPC UA, DDS, mTLS, and a protected
  local service boundary.
- An anytime-valid evidence process for persistent behavioral contradiction.

The modeled monitor held nominal sequence false alarms to 0.37% while detecting
90.3% of persistent modeled attacks at an anytime false-alarm target of 1%.
The guarantee remains conditional on nominal-model calibration.

## NV061 - Predictive Movement

### Established baseline

- [TrAISformer](https://arxiv.org/abs/2109.03958) demonstrates transformer-based
  long-horizon AIS prediction.
- [Conformal trajectory prediction](https://arxiv.org/abs/2408.00374) shows how
  model-agnostic coverage regions can wrap trajectory predictors.
- Track-to-track fusion with unknown correlations is an established problem;
  covariance intersection is a conservative solution.

### Defensible delta

- Do not compete solely on long-horizon neural prediction.
- Combine a fast predictor with custody confidence, association uncertainty,
  conformal coverage regions, and mission-priority hierarchy.
- Use covariance intersection when correlation between government,
  commercial, and organic tracks is unavailable.
- Preserve uncertainty in the operator output instead of converting every
  prediction into a falsely precise point.

Held-out AIS testing achieved 92.9% empirical coverage for a 90% target. Under
strong unknown sensor correlation, naive fusion covered only 83.5% of nominal
95% ellipses, while covariance intersection covered 97.1%.

When held-out forecast errors were scaled by 1.5 to model distribution shift,
static conformal coverage fell to 85.4%. A causal rolling recalibration using
only previously realized errors recovered 88.4% coverage after warmup. This
does not eliminate the transition period after abrupt shift, but it provides a
measurable degraded-operation response.

## NV062 - Secure Commercial Tasking

### Established baseline

Commercial providers already support automated tasking interfaces, encryption,
and workflow APIs. PQC and hybrid cryptography alone are not a complete
innovation claim.

### Defensible delta

- A task is a purpose-bound transaction with classification, provider,
  validity, approval, maximum-use, replay, cancellation, return-data, and
  retention semantics.
- Provider-specific schemas sit behind one government-owned assurance contract.
- Cryptographic agility allows hybrid algorithms to change without changing the
  mission transaction contract.
- Every state transition produces signed evidence suitable for a control
  package, while explicitly avoiding an authorization claim.

The dependency-safe crypto-agility result supports the transition story, but a
credentialed collection task and an approved IL5/IL6 boundary remain decisive.

## NV063 - Maritime Pattern of Life

### Established baseline

- Transformer-based AIS monitoring and trajectory models are increasingly
  common; see the [2025 AIS transformer review](https://arxiv.org/abs/2505.07374).
- Online false-discovery-rate control for anomaly detection is an established
  statistical approach: [Online FDR control for anomaly detection](https://arxiv.org/abs/2112.03196).

### Defensible delta

- Maintain compact local state instead of a massive region-specific history.
- Separate a high-confidence tier from a broader watch tier with explicit
  alert-budget semantics.
- Bind alerts to authenticated composite tracks, covariance, identity quality,
  classification, and reason codes.
- Calibrate prediction regions and alert thresholds on independent tracks.

The local split-conformal experiment produced:

- high-confidence recall 50.9% with 3.5% observed false-discovery proportion;
- watch-tier recall 63.0% with 9.3% observed false-discovery proportion.

These are more useful and honest than one unqualified F1 value, but the anomaly
examples remain injected and do not establish hostile intent.

## NV065 - Adaptive Sensor Management

### Established baseline

- NASA technical literature describes multi-Bernoulli, POMDP,
  information-driven, and robust sensor-selection approaches:
  [NASA sensor-selection paper](https://ntrs.nasa.gov/api/citations/20240015368/downloads/sensoeSelection.pdf).
- Robust sequential submodular optimization is an established direction for
  target tracking and resource-constrained sensing:
  [Tzoumas, Jadbabaie, and Pappas](https://arxiv.org/abs/1909.11783).

### Defensible delta

- Characterize marginal contribution to fire-control-quality covariance.
- Handle unknown cross-correlation conservatively rather than double-counting
  information.
- Enforce beam, slew, dwell, revisit, duty-cycle, and mode constraints in a
  bounded native scheduler.
- Keep Phase I advisory and retain operator confirmation.
- Expose the expected gain, degraded gain, conflict, and uncertainty behind
  every recommendation.

The robust-scheduling simulation currently shows only a modest lower-tail
improvement. It should be presented as a working robustness framework awaiting
program-specific failure distributions, not as a decisive performance result.

## NP002 - Defensive C-UAS

### Established baseline

Multi-object tracking, random-finite-set filters, multi-Bernoulli sensor
selection, acoustic classification, and multimodal fusion are mature research
areas.

### Defensible delta

- Use the low-cost native runtime for defensive detection, tracking,
  identification, custody, and explainable escalation.
- Treat sensor estimates as potentially correlated and avoid overconfident
  fusion.
- Separate track existence, classification, behavior, and payload uncertainty.
- Fuse acoustic, EO, RF, and radar evidence without allowing one modality to
  silently dominate.
- Produce signed alerts and human-reviewable uncertainty.

The current work supports the detection/tracking/behavior lane. It does not
support a claim of complete Detect-Track-Identify-Assess-Neutralize coverage.

## Research references with direct architectural impact

- [Game-Theoretic Statistics and Safe Anytime-Valid Inference](https://projecteuclid.org/journals/statistical-science/volume-38/issue-4/Game-Theoretic-Statistics-and-Safe-Anytime-Valid-Inference/10.1214/23-STS894.pdf)
- [Time-Uniform Confidence Sequences](https://projecteuclid.org/journals/annals-of-statistics/volume-49/issue-2/Time-uniform-nonparametric-nonasymptotic-confidence-sequences/10.1214/20-AOS1991.pdf)
- [Robust Multi-Bernoulli Sensor Selection references through NASA NTRS](https://ntrs.nasa.gov/api/citations/20240015368/downloads/sensoeSelection.pdf)
- [Conformal Uncertainty under Distribution Shift for Trajectory Prediction](https://openreview.net/pdf?id=IvtWalTVRV)
