# Seven-Topic Phase I / TRL 3-4 Feasibility Lab

This lab tests seven FY26 Phase I topic mappings using the smallest
surrogate that answers each solicitation's feasibility question:

- `QSPARX`: cryptographic inventory, risk scoring, and PQC migration mapping
- `NV059`: DDIL zero-trust authorization and signed transaction receipts
- `NV061`: multi-object forecasting, change detection, and hierarchical priority
- `NV062`: secure commercial task envelopes, integrity, and replay prevention
- `NV063`: explainable low-history maritime pattern-of-life anomaly detection
- `NV065`: covariance-aware advisory sensor resource allocation
- `NP002`: explainable UAS swarm behavior and anomaly monitoring

The original experiments are deliberately low fidelity. The TRL 3/4 campaign
adds real PQC operations, a PIV-style certificate path, a Modbus/TCP adapter, a
hybrid secure-task gateway, official NOAA AIS input, noisy multi-target
association, baselines, ablations, robustness runs, and signed evidence.

## Architecture

Python is the research and evaluation plane. A compact Rust crate under
`native/assure-kernel` now provides the deterministic mission-execution kernels,
a fixed authenticated binary track frame, bounded scheduling, release
benchmarks, and a stable C ABI for C/C++ integration.

See:

- `docs/DEPLOYMENT_ARCHITECTURE.md`
- `docs/PROPOSAL_EXECUTION_STRATEGY.md`
- `docs/STATE_OF_ART_AND_NOVELTY.md`
- `docs/THREAT_MODEL.md`
- `docs/DATA_AND_MODEL_CARDS.md`
- `docs/TOPIC_TECHNICAL_OBJECTIVES.md`
- `docs/RELEASE_READINESS.md`
- `docs/CURRENT_AND_POTENTIAL_ASSESSMENT.md`
- `docs/PHASE1_GO_NO_GO.md`
- `docs/EXTERNAL_ACCESS_PACKAGES.md`
- `docs/NP002_FIELD_VALIDATION_PATH.md`
- `docs/WIRE_PROTOCOL.md`
- `docs/WIN_GATES.md`
- `SECURITY.md`
- `native/assure-kernel/include/assure_kernel.h`

## Simplest verification

```bash
make verify
```

Run every local test:

```bash
make full
```

Run the repeated, process-isolated native benchmark:

```bash
make independent-benchmark
```

Run dense-crossing custody and assignment comparisons:

```bash
make dense-crossing
```

Run the frozen Puget-to-New-York trajectory evaluation:

```bash
make frozen-region
```

Rerun the complete Wave 5 evidence campaign:

```bash
make campaign
```

Run the theory-driven uncertainty, fusion, crypto-agility, and robust-scheduling
campaign:

```bash
make theory
```

Install the measured dependency set reproducibly with:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt -c requirements-lock.txt
```

Run:

```bash
python3 run_experiments.py
python3 -m unittest -v test_experiments.py
python3 run_robustness_sweep.py
```

Full TRL 3/4 campaign:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python prepare_noaa_ais.py
.venv/bin/python run_trl4_campaign.py
.venv/bin/python -m unittest -v test_trl4_campaign.py
```

Compile and verify the topic-tuned PZDR/RTVLAS systems:

```bash
.venv/bin/python compile_tuned_systems.py
.venv/bin/python -m unittest -v test_assure_core.py
```

Run the next-step extension campaign:

```bash
.venv/bin/python prepare_opensky.py
.venv/bin/python run_extended_campaign.py
.venv/bin/python run_extension_robustness.py
.venv/bin/python -m unittest -v test_trl4_extensions.py
```

Run the secure-transport and real-sensor third wave:

```bash
.venv/bin/python prepare_nasa_uas_acoustics.py
.venv/bin/python prepare_opensky.py \
  --output data/external/opensky/puget_sound_states_long.json \
  --samples 36 --interval 5
.venv/bin/python run_wave3_campaign.py
.venv/bin/python run_wave3_robustness.py
.venv/bin/python -m unittest -v test_wave3_campaign.py
```

Run the all-topics-above-90 fourth wave:

```bash
.venv/bin/python run_wave4_campaign.py
.venv/bin/python run_wave4_robustness.py
.venv/bin/python -m unittest -v test_wave4_campaign.py
```

Run the all-topics-above-95 fifth wave:

```bash
.venv/bin/python run_wave5_campaign.py
.venv/bin/python run_wave5_robustness.py
.venv/bin/python -m unittest -v test_wave5_campaign.py
```

Outputs:

- `results/independent_benchmark/independent_benchmark.json`
- `results/independent_benchmark/INDEPENDENT_BENCHMARK.md`
- `results/dense_crossing/dense_crossing_results.json`
- `results/dense_crossing/DENSE_CROSSING_REPORT.md`
- `results/frozen_region/frozen_region_results.json`
- `results/frozen_region/FROZEN_REGION_REPORT.md`
- `results/phase1_feasibility_results.json`
- `results/phase1_feasibility_results.md`
- `results/robustness_sweep.json`
- `results/trl4_campaign/TRL4_CAMPAIGN_REPORT.md`
- `results/trl4_campaign/campaign_results.json`
- `results/trl4_campaign/match_scores.json`
- `results/trl4_campaign/NEXT_TRL4_EXPERIMENTS.md`
- `results/tuned_systems/TUNED_SYSTEM_ARCHITECTURE.md`
- `results/tuned_systems/TUNED_SYSTEM_SCORECARD.md`
- `results/tuned_systems/tuned_systems.json`
- `results/tuned_systems/philosophy_ablations.json`
- `results/trl4_extensions/EXTENDED_CAMPAIGN_REPORT.md`
- `results/trl4_extensions/extended_campaign_results.json`
- `results/trl4_extensions/extended_match_scores.json`
- `results/trl4_extensions/EXTENSION_ROBUSTNESS.md`
- `results/trl4_extensions/extension_robustness.json`
- `results/trl4_wave3/WAVE3_CAMPAIGN_REPORT.md`
- `results/trl4_wave3/wave3_campaign_results.json`
- `results/trl4_wave3/wave3_match_scores.json`
- `results/trl4_wave3/WAVE3_ROBUSTNESS.md`
- `results/trl4_wave3/wave3_robustness.json`
- `results/trl4_wave4/WAVE4_CAMPAIGN_REPORT.md`
- `results/trl4_wave4/wave4_campaign_results.json`
- `results/trl4_wave4/wave4_match_scores.json`
- `results/trl4_wave4/WAVE4_ROBUSTNESS.md`
- `results/trl4_wave4/wave4_robustness.json`
- `results/trl4_wave5/WAVE5_CAMPAIGN_REPORT.md`
- `results/trl4_wave5/wave5_campaign_results.json`
- `results/trl4_wave5/wave5_match_scores.json`
- `results/trl4_wave5/WAVE5_ROBUSTNESS.md`
- `results/trl4_wave5/wave5_robustness.json`
- `results/trl4_wave5/TRANSITION_GATE_CHECKLIST.md`
