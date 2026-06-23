# Independent Repeated Native Benchmark

Generated: `2026-06-23T06:01:26.603881+00:00`

- Host: `macOS-26.1-arm64-arm-64bit`
- Machine: `arm64`
- Rust: `rustc 1.94.1 (e408947bf 2026-03-25)`
- Executable SHA-256: `27fe1adcd9d14a44618e6e1b7372c559c92342505a7f14a128767b77d7f32ad8`
- Source-tree SHA-256: `8d2806279fb501d03a023c688b1227b2b171ea4c13e27a897aa546df84d2a549`

## Method

- Release binary built once before measurement.
- One unreported warm-up process.
- 20 independent benchmark processes
  at 150,000 iterations.
- 15 independent scaling processes.
- 20 independent conformance
  processes compared for byte-equivalent JSON results.
- Percentiles below are across process-level results, not individual
  operations and not worst-case execution-time bounds.

## Results

| Path | Median | Process p95 | Process max | CV |
| --- | ---: | ---: | ---: | ---: |
| Authenticated 136-byte decode | 1.031 us | 1.167 us | 1.325 us | 8.1% |
| 240-candidate schedule | 3.332 us | 3.913 us | 5.967 us | 17.0% |
| 1,000-object association | 365.087 us | 441.041 us | 451.598 us | 8.7% |
| 10,000-object association | 4.646 ms | 4.711 ms | 4.711 ms | 2.9% |
| 3,840-candidate schedule | 220.450 us | 251.423 us | 251.423 us | 6.2% |

Median benchmark-process wall time was
`308.84 ms`; median scaling-process wall time was
`82.45 ms`.

## Sanity gates

These intentionally loose gates detect catastrophic regressions on a shared
host. They are not sponsor acceptance criteria.

| Gate | Result | Evidence |
| --- | --- | --- |
| deterministic_conformance | PASS | 20 independent processes agreed |
| authenticated_decode | PASS | process p95 1.167 us < 50 us |
| bounded_scheduler | PASS | 3,840-candidate process p95 251.423 us < 5 ms |
| sparse_association | PASS | 10,000-object process p95 4.711 ms < 50 ms |

## Interpretation limits

This benchmark establishes executable feasibility and run-to-run behavior on
this host. It does not establish target-platform WCET, real-time scheduling,
end-to-end sensor latency, power/thermal performance, dense-clutter tracking
quality, or operational mission effectiveness. The association geometry is
spatially gated and favorable. A representative Linux x86/ARM hardware matrix,
CPU pinning, fixed power state, memory profiling, dense-crossing accuracy, and
sponsor data remain required.
