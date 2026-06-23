# Native Kernel Efficiency Report

Host: `macOS-26.1-arm64-arm-64bit`

This is a release-mode host measurement, not target-hardware worst-case
execution-time evidence.

| Measurement | Result |
| --- | ---: |
| Evidence update | 100.6 ns/op |
| Custody and priority | 5.2 ns/op |
| Authenticated track decode mean / batch-p99 | 1011.6 / 1058.2 ns |
| 240-candidate schedule mean / batch-p99 | 3345.5 / 4335.8 ns |
| 1,000-object association mean / batch-p99 | 365.8 / 379.7 us |
| 10,000-object sparse association | 4.68 ms/update |
| 3,840-candidate bounded schedule | 226.1 us/update |
| Authenticated track frame | 136 bytes |
| Release executable | 441.2 KiB |

The verification gate is intentionally loose enough to tolerate shared CI
hosts while still detecting major regressions. Representative x86 and ARM
hardware profiling remains a Phase I transition task. Percentiles are computed
over repeated batch-average measurements and are not WCET proofs.
