# Independent Repeated Native Benchmark

Generated: `2026-06-23T16:54:02.135381+00:00`

- Host: `macOS-26.1-arm64-arm-64bit`
- Machine: `arm64`
- Rust: `rustc 1.94.1 (e408947bf 2026-03-25)`
- Executable SHA-256: `27fe1adcd9d14a44618e6e1b7372c559c92342505a7f14a128767b77d7f32ad8`
- Source-tree SHA-256: `4d28ba65b518f4f7c221ba3d88077ee3410dedbdc4379f5d78a97e2a60ed7e46`

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
| Authenticated 136-byte decode | 1.009 us | 1.224 us | 2.042 us | 21.7% |
| 240-candidate schedule | 3.316 us | 4.032 us | 5.266 us | 13.5% |
| 1,000-object association | 355.562 us | 408.920 us | 503.223 us | 9.9% |
| 10,000-object association | 4.540 ms | 4.746 ms | 4.746 ms | 2.0% |
| 3,840-candidate schedule | 225.360 us | 283.977 us | 283.977 us | 8.6% |

Median benchmark-process wall time was
`290.36 ms`; median scaling-process wall time was
`81.18 ms`.

## Sanity gates

These intentionally loose gates detect catastrophic regressions on a shared
host. They are not sponsor acceptance criteria.

| Gate | Result | Evidence |
| --- | --- | --- |
| deterministic_conformance | PASS | 20 independent processes agreed |
| authenticated_decode | PASS | process p95 1.224 us < 50 us |
| bounded_scheduler | PASS | 3,840-candidate process p95 283.977 us < 5 ms |
| sparse_association | PASS | 10,000-object process p95 4.746 ms < 50 ms |

## Interpretation limits

This benchmark establishes executable feasibility and run-to-run behavior on
this host. It does not establish target-platform WCET, real-time scheduling,
end-to-end sensor latency, power/thermal performance, dense-clutter tracking
quality, or operational mission effectiveness. The association geometry is
spatially gated and favorable. A representative Linux x86/ARM hardware matrix,
CPU pinning, fixed power state, memory profiling, dense-crossing accuracy, and
sponsor data remain required.
