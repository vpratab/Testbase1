# Theory-Driven Assurance Campaign

Generated: 2026-06-23T03:11:22Z

These are locally reproducible research results, not operational guarantees.

| Contribution | Measured result | Topic leverage |
| --- | --- | --- |
| Conformal trajectory regions | global coverage 0.929; speed-conditioned coverage 0.908 | NV061, NV063 |
| FDR-controlled PoL alerts | high-confidence recall/FDP 0.509/0.035; watch recall/FDP 0.630/0.093 | NV063 |
| Distribution-shift adaptation | at 1.5x error scale, static coverage 0.854; rolling coverage after warmup 0.884 | NV061, NV063 |
| Unknown-correlation fusion | naive 95% coverage 0.835; covariance-intersection coverage 0.971 | NV061, NV065, NP002 |
| Anytime-valid access evidence | false-alarm rate 0.0037; attack detection 0.903 | NV059, QSPARX |
| Dependency-safe crypto agility | unsafe ordering violations 91; safe violations 0 | QSPARX, NV062 |
| Robust sensor scheduling | fifth-percentile utility improvement 0.3% | NV065, NP002 |

## Interpretation

- Conformal methods add empirically calibrated uncertainty and alert-budget
  semantics without replacing the existing predictor or PoL detector.
- Covariance intersection prevents unjustified confidence when sensor
  cross-correlation is unknown.
- The access e-process supports continuous monitoring with an anytime-valid
  false-alarm interpretation under a calibrated nominal model.
- Dependency-safe scheduling turns crypto inventory into executable migration
  order while preserving interoperability.
- Robust scheduling trades a small amount of nominal optimism for stronger
  degraded-sensor performance.

Every result retains an explicit boundary in the JSON artifact.
