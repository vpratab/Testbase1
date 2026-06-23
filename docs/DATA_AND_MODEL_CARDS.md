# Data and Model Cards

## NOAA AIS maritime data

- Purpose: nominal trajectory forecasting, PoL calibration, synthetic-deviation
  studies, and scalable surface-track processing.
- Strength: official real vessel movement data.
- Limitation: public cooperative AIS is not an operational composite-track
  feed and does not contain authoritative hostile-intent labels.
- Processing: time ordering, deduplication, coordinate projection, interpolation,
  minimum-duration and motion-quality screening.
- Prohibited claim: measured injected-anomaly performance equals hostile-contact
  detection performance.

### Independent region/date holdout

- Source: official NOAA/USCG AIS archive for March 15, 2020.
- Region: New York Harbor and approaches.
- Use: frozen-parameter transfer evaluation after all PoL thresholds and
  forecast parameters were selected on the February 15, 2020 Puget Sound
  subset.
- Result boundary: public AIS does not provide malicious-behavior truth.
  Reported nominal-proxy alert rates use quality-screened public tracks;
  controlled anomalies provide detection truth.
- Artifact: `results/frozen_region/frozen_region_results.json`.

## OpenSky aviation data

- Purpose: air-track forecasting and cross-domain anomaly experiments.
- Strength: real ADS-B-derived aircraft trajectories.
- Limitation: incomplete coverage, public cooperative reporting, and no
  authoritative threat labels.

## NASA UAS acoustics

- Purpose: external real-hardware acoustic classification and recording-level
  holdout evaluation.
- Strength: calibrated recordings and flight metadata.
- Limitation: not synchronized with operational radar, EO, RF, payload, weather,
  and clutter truth; current labels do not establish a complete C-UAS taxonomy.

## Synthetic and injected data

Synthetic scenarios are used for controlled ablations, attack onset, clutter,
swarm behavior, radar constraints, cyber misuse, and distribution-shift stress.
They are valuable because ground truth is exact, but they can share assumptions
with the algorithm under test.

Every result should identify whether truth is:

- real labeled;
- real nominal with injected event;
- simulated;
- rule-generated;
- externally observed but unlabeled.

## Maritime anomaly model

- Model: grouped-track random forest using motion and sequential PoL features.
- Training: nominal tracks and multiple injected deviation families.
- Validation: track-grouped folds; independent tracks do not cross folds.
- Calibration: split-conformal p-values and bounded alert batches.
- Output: high-confidence and watch tiers with observed false-discovery
  proportions.
- Limitation: random-forest probability is not a calibrated hostility
  probability.

## Forecast model

- Model: low-compute smoothed-velocity/Kalman-style predictor.
- Rationale: transparent, fast, and suitable for native implementation.
- Uncertainty: split-conformal trajectory regions and rolling recalibration.
- Limitation: abrupt distribution shift temporarily breaks static coverage;
  rolling adaptation is causal but not instantaneous.

## Sequential evidence models

- Model families: EWMA/CUSUM-style accumulation and Bernoulli likelihood-ratio
  e-process.
- Benefit: persistent weak contradiction can be detected without treating one
  sample as truth.
- Limitation: event rates and thresholds must be calibrated on sponsor-relevant
  nominal behavior.

## Sensor-allocation model

- Model: covariance/information utility with hard resource constraints,
  conservative fusion, and minimax degradation studies.
- Limitation: current radar and degradation parameters are generic surrogates.
  Program-specific fire-control-quality metrics are required.

## Model-change control

A Phase II process should version:

- feature definitions;
- calibration population;
- thresholds and alert budget;
- training data fingerprints;
- dependency and compiler versions;
- native code identity;
- operator-approved deployment profile.
