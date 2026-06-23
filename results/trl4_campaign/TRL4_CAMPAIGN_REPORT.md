# Seven-Topic TRL 3/4 Laboratory Campaign

Generated: 2026-06-21T21:23:25Z

## Outcome

All seven demonstrators completed their laboratory campaign. The score is a
measured match to the current Phase I requirement, not a probability of award.

| Rank | Topic | Match / 100 | Estimated TRL |
| ---: | --- | ---: | ---: |
| 1 | NV061 | 83.6 | 3.5 |
| 2 | NV059 | 83.5 | 4.0 |
| 3 | QSPARX | 82.9 | 3.6 |
| 4 | NV063 | 79.3 | 3.9 |
| 5 | NV065 | 76.5 | 3.5 |
| 6 | NV062 | 76.3 | 3.7 |
| 7 | NP002 | 72.1 | 3.5 |

## Measured highlights

- **QSPARX:** scanned `201` real source/configuration files and `128` host trust-store certificates; actual ML-KEM-768 and ML-DSA-65 operations passed `120` iterations; AI migration-risk F1 `0.981`.
- **NV059:** real P-256 X.509 chain, challenge response, revocation, and Modbus/TCP parsing; authorization F1 `1.000`; p95 `13.2` us.
- **NV062:** bidirectional hybrid X25519 + ML-KEM-768 encryption and Ed25519 + ML-DSA-65 signatures over four provider schemas through a localhost HTTP gateway; p95 `8618.9` us; all task returns, tamper, and replay cases verified correctly.
- **NP002:** noisy multi-UAS detections with 91% probability of detection and clutter; association accuracy `0.845`; behavior F1 `1.000`.
- **NV061:** synthetic forecast improvement `68.4%`; real-AIS forecast improvement `6.2%`; priority recall `0.730`; association accuracy `0.991`.
- **NV063:** official NOAA AIS input; `194` tracks screened; held-out/injected F1 `0.784` and FPR `0.175`.
- **NV065:** four-radar low-fidelity advisory model; novel-threat covariance improvement `83.2%`; p95 `484.9` us.

## Robustness

- QSPARX risk F1 mean/min: `0.981` / `0.977`.
- NV059 authorization F1 mean/min: `1.000` / `1.000`.
- NV063 real-AIS F1 mean/min: `0.784` / `0.759`.
- NP002 swarm F1 mean/min: `0.997` / `0.983`.
- NV061 forecast improvement mean/min: `66.0%` / `64.6%`.
- NV065 novel-threat improvement mean/min: `82.8%` / `81.0%`.

## Honest remaining blockers

| Topic | Largest blocker to a stronger TRL 4 claim |
| --- | --- |
| QSPARX | Host trust-store and repository discovery work, but there is no live AFDW/CMDB/network-endpoint evaluation |
| NV059 | No actual network microsegmentation, CAC middleware, DDS, or OPC-UA integration |
| NV062 | No commercial provider API, return imagery path, or IL-5/IL-6 accreditation environment |
| NP002 | No real EO/RF/radar UAS sensor data and no payload/type classifier |
| NV061 | NOAA AIS is exercised, but other sensor domains and an operational identity/custody corpus are absent |
| NV063 | AIS false-alert rate remains material; ADS-B and SSDS composite tracks remain simulated |
| NV065 | Radar parameters and SSDS tasking constraints remain open low-fidelity surrogates |

## Interpretation

- `90+` means the laboratory artifact covers nearly every Phase I feasibility
  element; remaining gaps are mostly customer environment or transition access.
- `80-89` means strong Phase I technical match with one or two meaningful
  integration/domain gaps.
- `70-79` means a responsive and testable Phase I concept, but reviewers will
  need to accept a larger transition or realism assumption.
- `60-69` means the core mechanism works in the laboratory, but a major
  customer-domain integration is still missing.

The evidence supports pursuing all seven as two shared background-technology
families, not seven independent products.

The `pqcrypto` ML-KEM/ML-DSA implementation used here exercises the NIST
algorithms but is not claimed to be a FIPS-validated cryptographic module.

## Data and standards sources

- NOAA/USCG AIS day:
  https://coast.noaa.gov/htdata/CMSP/AISDataHandler/2020/AIS_2020_02_15.zip
- QSPARX topic:
  https://www.sbir.gov/topics/12764
- NIST FIPS 203:
  https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204:
  https://csrc.nist.gov/pubs/fips/204/final
- NIST FIPS 205:
  https://csrc.nist.gov/pubs/fips/205/final
- Navy topics:
  https://www.navysbir.com/topics26_3.htm
