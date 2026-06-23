# Native Kernel Efficiency Report

Host: `macOS-26.1-arm64-arm-64bit`

This is a release-mode host measurement, not target-hardware worst-case
execution-time evidence.

| Measurement | Result |
| --- | ---: |
| Evidence update | 86.5 ns/op |
| Custody and priority | 5.4 ns/op |
| Authenticated track decode mean / batch-p99 | 1085.6 / 1036.3 ns |
| 240-candidate schedule mean / batch-p99 | 3340.1 / 3776.7 ns |
| 1,000-object association mean / batch-p99 | 354.9 / 382.4 us |
| 10,000-object sparse association | 4.65 ms/update |
| 3,840-candidate bounded schedule | 227.9 us/update |
| Authenticated track frame | 136 bytes |
| Release executable | 441.2 KiB |

The verification gate is intentionally loose enough to tolerate shared CI
hosts while still detecting major regressions. Representative x86 and ARM
hardware profiling remains a Phase I transition task. Percentiles are computed
over repeated batch-average measurements and are not WCET proofs.
