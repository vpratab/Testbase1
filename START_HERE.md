# Start Here

This repository is a Phase I SBIR feasibility lab for seven defense-relevant
software concepts. It is designed to be understandable to a reviewer, proposal
writer, engineer, or partner who did not watch the work being built.

It contains working code, tests, benchmark evidence, proposal-readiness
packets, and honest boundaries. It does not claim award probability,
classified-environment validation, live operational deployment, or partner
commitments.

## What this is

The project turns two internal design philosophies, PZDR and RTVLAS, into
topic-specific Phase I evidence.

- **PZDR** is used where the key question is secure authority, cryptographic
  migration, task authorization, replay prevention, or evidence.
- **RTVLAS** is used where the key question is tracking, anomaly detection,
  prioritization, sensor allocation, uncertainty, or custody.

Python is the research and evaluation layer. Rust is the compact native
execution layer for deterministic mission kernels and C/C++ integration.

## The seven topics in simple terms

| Topic | Plain meaning | Current status |
| --- | --- | --- |
| QSPARX | Find vulnerable cryptography and plan safe post-quantum migration | Conditional GO |
| NV059 | Zero-trust access control for combat-system data | GO |
| NV061 | Predict and prioritize maritime object movement | GO |
| NV062 | Securely task commercial satellites/assets | Conditional GO |
| NV063 | Detect unusual behavior in crowded maritime environments | GO |
| NV065 | Recommend better ship sensor tasking | GO |
| NP002 | Defensive C-UAS sensing, tracking, identification, and handoff lane | Partner GO |

Status meanings:

- **GO:** internally Phase I proposal-ready now.
- **Conditional GO:** technically credible, but proposal should name the
  first-month data/access plan.
- **Partner GO:** technically credible only if a test-site, data, system-owner,
  or integration partner is identified.

## The fastest way to understand the repo

Read these in order:

1. `results/completion_audit/COMPLETION_AUDIT.md`
   Final audit of what is complete and what still needs external access.
2. `results/go4_comparison/GO4_COMPETITIVE_ALIGNMENT.md`
   Solicitation-aligned GO-4 evidence for NV059, NV061, NV063, and NV065.
3. `results/go4_enhanced/GO4_ENHANCED_REPORT.md`
   Harder generated metrics for the four highest-readiness topics.
4. `docs/GO4_DEEP_RESEARCH_AND_HARDENING.md`
   What changed after the deeper research/code-hardening pass.
5. `results/proposal_readiness/TOPIC_PROPOSAL_PACKETS.md`
   One proposal-ready packet per topic.
6. `docs/PHASE1_GO_NO_GO.md`
   Topic status, scores, submission rule, and external blockers.
7. `docs/CURRENT_AND_POTENTIAL_ASSESSMENT.md`
   Truthful current-vs-potential assessment.
8. `results/trl4_wave5/EVIDENCE_INDEX.md`
   Map from topics to strongest measured evidence.
9. `docs/EXTERNAL_ACCESS_PACKAGES.md`
   Exact first-month data and integration requests.
10. `docs/PARTNER_OUTREACH_TEMPLATES.md`
   Draft outreach for the remaining partner-dependent paths.

## What is proven now

- Native execution is fast and repeatable.
- Authenticated binary track frames, replay rejection, and C/C++ integration
  work.
- Secure task envelopes, negative tests, provider schemas, and return-data
  verification are implemented.
- Dense-crossing custody testing improved 256-object assignment accuracy from
  57.4% to 85.2% and reduced identity switches by 56.8%.
- Frozen Puget-Sound-to-New-York AIS forecasting beat hold and raw-velocity
  baselines by about 21%.
- The single-tier maritime anomaly threshold failed on transfer and is
  documented. The supported design is a watch tier plus high-confidence tier.
- Every topic has a first-month proof, Base demo, Option demo, failure
  condition, and overclaim boundary.

## What is not proven

Software and public data cannot replace:

- AFDW inventory or approved range access for QSPARX;
- DoD identity and combat-network access for NV059;
- operational composite tracks and analyst dispositions for NV061;
- live credentialed provider tasking for NV062;
- SSDS replay and operator dispositions for NV063;
- approved radar/task parameters for NV065;
- synchronized C-UAS field truth and an integration owner for NP002.

Those are explicitly tracked so the repo does not overclaim.

## How to verify

Create the environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt -c requirements-lock.txt
```

Run the normal verification:

```bash
make verify
```

Run all local tests:

```bash
make full
```

Regenerate proposal readiness and completion audit:

```bash
make proposal-readiness
make completion-audit
```

Regenerate the solicitation-aligned GO-4 evidence:

```bash
make go4
```

Important recent full verification result:

- 79 Python tests passed.
- 9 Rust tests passed.
- C ABI smoke test passed.
- Rust formatting and clippy passed.
- Native benchmark artifacts regenerated.
- Source and release manifests regenerated.
- Release manifest includes 19 evidence artifacts.

## Key generated evidence

| Evidence | File |
| --- | --- |
| Completion audit | `results/completion_audit/COMPLETION_AUDIT.md` |
| GO-4 solicitation alignment | `results/go4_comparison/GO4_COMPETITIVE_ALIGNMENT.md` |
| GO-4 enhanced evidence | `results/go4_enhanced/GO4_ENHANCED_REPORT.md` |
| GO-4 research hardening note | `docs/GO4_DEEP_RESEARCH_AND_HARDENING.md` |
| Proposal packets | `results/proposal_readiness/TOPIC_PROPOSAL_PACKETS.md` |
| Independent benchmark | `results/independent_benchmark/INDEPENDENT_BENCHMARK.md` |
| Dense crossing campaign | `results/dense_crossing/DENSE_CROSSING_REPORT.md` |
| Frozen region AIS campaign | `results/frozen_region/FROZEN_REGION_REPORT.md` |
| Release manifest | `results/supply_chain/release_manifest.json` |
| Evidence index | `results/trl4_wave5/EVIDENCE_INDEX.md` |

## Repository boundaries

The tracked repository includes processed public datasets and generated
evidence artifacts needed to understand the work. It intentionally does not
track virtual environments, Rust build outputs, downloaded raw archives, or
external credentials.

This is proposal-readiness evidence, not operational software for deployment.
