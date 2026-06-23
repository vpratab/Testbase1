# Dense Crossing Association Campaign

Controlled synthetic truth compares the bounded greedy policy, a new
sparse component-optimal policy, and a dense Hungarian baseline.

| Objects | Method | Mean accuracy | Mean switches | Mean p95 latency | Candidate fraction |
| ---: | --- | ---: | ---: | ---: | ---: |
| 16 | greedy | 0.7026 | 30.7 | 64.4 us | 0.1400 |
| 16 | component | 0.7480 | 22.8 | 341.0 us | 0.1407 |
| 16 | custody_component | 0.9946 | 0.3 | 340.0 us | 0.1405 |
| 16 | hungarian | 0.7480 | 22.8 | 64.8 us | 0.1407 |
| 64 | greedy | 0.6209 | 182.8 | 240.3 us | 0.0334 |
| 64 | component | 0.6518 | 169.5 | 1382.5 us | 0.0338 |
| 64 | custody_component | 0.9448 | 31.8 | 1325.5 us | 0.0338 |
| 64 | hungarian | 0.6518 | 169.5 | 508.5 us | 0.0338 |
| 256 | greedy | 0.5737 | 901.1 | 1099.5 us | 0.0078 |
| 256 | component | 0.5748 | 910.6 | 4884.3 us | 0.0080 |
| 256 | custody_component | 0.8523 | 388.8 | 4846.6 us | 0.0080 |
| 256 | hungarian | 0.5748 | 910.6 | 11198.7 us | 0.0080 |

## Interpretation

The custody-aware method uses a noisy six-dimensional stable
signature as a surrogate for available source, type, RF, acoustic,
or appearance evidence. It is initialized before the crossing and
updated from assigned detections. Truth identity is used only for
scoring after assignment, never in the assignment cost.

In the 256-object case it improved mean assignment accuracy by
`48.6%` relative to greedy and reduced identity
switches by `56.8%`. Its mean p95 Python
latency was `4.85 ms`.

This campaign tests association quality under deliberately ambiguous
crossings. It does not establish performance on Navy sensor data.
The component-optimal method keeps the sparse gate and escalates only
ambiguous connected components. Components above the declared cap
fall back to bounded greedy assignment and are counted explicitly.
