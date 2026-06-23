# Independent Repeated Native Benchmark

Generated: `2026-06-23T16:57:59.426123+00:00`

- Host: `macOS-26.1-arm64-arm-64bit`
- Machine: `arm64`
- Rust: `rustc 1.94.1 (e408947bf 2026-03-25)`
- Executable SHA-256: `27fe1adcd9d14a44618e6e1b7372c559c92342505a7f14a128767b77d7f32ad8`
- Source-tree SHA-256: `7eb72f877fee82107257b544fc3f584ed8a9b3fdc764515c70937ba887a5f36b`

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
| Authenticated 136-byte decode | 1.009 us | 1.219 us | 1.783 us | 17.3% |
| 240-candidate schedule | 3.295 us | 4.304 us | 5.070 us | 14.3% |
| 1,000-object association | 354.948 us | 452.110 us | 489.871 us | 11.1% |
| 10,000-object association | 4.600 ms | 5.152 ms | 5.152 ms | 4.2% |
| 3,840-candidate schedule | 212.137 us | 239.281 us | 239.281 us | 4.8% |

Median benchmark-process wall time was
`288.26 ms`; median scaling-process wall time was
`81.75 ms`.

## Sanity gates

These intentionally loose gates detect catastrophic regressions on a shared
host. They are not sponsor acceptance criteria.

| Gate | Result | Evidence |
| --- | --- | --- |
| deterministic_conformance | PASS | 20 independent processes agreed |
| authenticated_decode | PASS | process p95 1.219 us < 50 us |
| bounded_scheduler | PASS | 3,840-candidate process p95 239.281 us < 5 ms |
| sparse_association | PASS | 10,000-object process p95 5.152 ms < 50 ms |

## Interpretation limits

This benchmark establishes executable feasibility and run-to-run behavior on
this host. It does not establish target-platform WCET, real-time scheduling,
end-to-end sensor latency, power/thermal performance, dense-clutter tracking
quality, or operational mission effectiveness. The association geometry is
spatially gated and favorable. A representative Linux x86/ARM hardware matrix,
CPU pinning, fixed power state, memory profiling, dense-crossing accuracy, and
sponsor data remain required.
