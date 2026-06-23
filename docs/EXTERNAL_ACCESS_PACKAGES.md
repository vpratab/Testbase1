# First-Month Data and Integration Packages

These packages convert external dependencies into bounded Phase I requests.
They do not assume classified or operational access before award.

| Topic | Minimum first-month request | What is not needed | Executable fallback |
| --- | --- | --- | --- |
| QSPARX | sanitized 25-50 asset inventory, cryptographic mechanism metadata, dependency edges, key-storage class, and approved migration policy | private keys, mission data, or production write access | sponsor-approved replica using the same schemas and dependency patterns |
| NV059 | test identities, compartment/purpose matrix, representative policy decisions, two or more network segments, and protocol endpoints | operational combat data or production credentials | isolated combat-network surrogate with sponsor-approved policy cases |
| NV061 | de-identified multi-source tracks with timestamps, source, covariance, identity continuity events, and analyst priority dispositions | platform names, intelligence content, or targeting decisions | public AIS/ADS-B plus sponsor-authored identity and priority scenarios |
| NV062 | Capella or Umbra sandbox credential, approved task schema, approval/cancellation states, and representative return metadata | paid collection, classified coordinates, or production ordering authority | live public OpenAPI/schema conformance plus simulated sandbox lifecycle and real open-data returns |
| NV063 | representative regional replay, interface schema, storage ceiling, and operator watch/high-confidence dispositions | weapons data or operational threat identity | frozen public AIS/ADS-B regional transfer with injected controlled deviations |
| NV065 | reference combat-system architecture, sensor task parameters, hard conflicts, deadline semantics, and track-quality definitions | classified waveform implementation or automatic sensor control | literature-grounded sensor surrogates with operator-advisory output |
| NP002 | selected C-UAS platform/interface, synchronized sensor recordings, target class, custody truth, clutter/weather, and defeat-system handoff timestamps | defeat-system control authority or sensitive engagement logic | NASA acoustics plus synthetic synchronized radar/EO/RF evidence and bounded handoff contract |

## NV062 public integration path

Current public provider material makes a pre-credential Phase I integration
plan credible:

- Capella documents a no-cost sandbox and REST tasking APIs.
- Umbra publishes production and developer-sandbox tasking endpoints.
- The lab already reaches Capella's live OpenAPI description, validates Umbra
  task schemas, exercises lifecycle states, and verifies real Capella and Umbra
  open-data returns.

The central proposal claim should therefore be government-owned,
provider-neutral authority and evidence—not merely encrypted automated tasking.

## Access-risk rule

Each proposal should:

1. identify the exact requested fields and interface;
2. state that no secrets or production write access are required for the Base;
3. provide a sponsor-approved surrogate fallback;
4. make representative access a measured Option or Phase II transition gate;
5. avoid claiming the fallback is operational validation.

## Public provider references

- [Capella tasking API](https://docs.capellaspace.com/api/tasking/)
- [Capella authentication and sandbox](https://docs.capellaspace.com/authentication/)
- [Umbra API overview](https://docs.canopy.umbra.space/docs/overview/)
- [Umbra create task](https://docs.canopy.umbra.space/reference/createtask)
- [Capella open-data catalog](https://capella-open-data.s3.us-west-2.amazonaws.com/stac/catalog.json)
- [Umbra open-data catalog](https://s3.us-west-2.amazonaws.com/umbra-open-data-catalog/stac/catalog.json)
