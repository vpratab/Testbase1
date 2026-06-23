import unittest

from tools.independent_benchmark import (
    aggregate_benchmarks,
    aggregate_scaling,
    nearest_rank,
    summarize,
)


class IndependentBenchmarkTests(unittest.TestCase):
    def test_nearest_rank_percentile(self) -> None:
        values = [5.0, 1.0, 4.0, 2.0, 3.0]
        self.assertEqual(nearest_rank(values, 0.50), 3.0)
        self.assertEqual(nearest_rank(values, 0.95), 5.0)

    def test_summary_retains_dispersion(self) -> None:
        result = summarize([1.0, 2.0, 3.0, 4.0])
        self.assertEqual(result["samples"], 4)
        self.assertEqual(result["minimum"], 1.0)
        self.assertEqual(result["median"], 2.5)
        self.assertEqual(result["p95"], 4.0)
        self.assertEqual(result["maximum"], 4.0)
        self.assertGreater(result["coefficient_of_variation"], 0.0)

    def test_benchmark_aggregate_is_across_processes(self) -> None:
        first = {
            "evidence_ns_per_operation": 1.0,
            "custody_priority_ns_per_operation": 2.0,
            "track_decode_ns_per_operation": 3.0,
            "scheduler_ns_per_operation": 4.0,
            "association_ns_per_operation": 5.0,
        }
        second = {key: value * 2.0 for key, value in first.items()}
        aggregate = aggregate_benchmarks([first, second])
        self.assertEqual(
            aggregate["track_decode_ns_per_operation"]["median"],
            4.5,
        )

    def test_scaling_aggregate_groups_by_size(self) -> None:
        runs = [
            {
                "association": [
                    {"size": 100, "ns_per_update": 10.0},
                    {"size": 1000, "ns_per_update": 100.0},
                ],
                "scheduler": [
                    {"size": 60, "ns_per_update": 6.0},
                    {"size": 240, "ns_per_update": 24.0},
                ],
            },
            {
                "association": [
                    {"size": 100, "ns_per_update": 20.0},
                    {"size": 1000, "ns_per_update": 200.0},
                ],
                "scheduler": [
                    {"size": 60, "ns_per_update": 12.0},
                    {"size": 240, "ns_per_update": 48.0},
                ],
            },
        ]
        aggregate = aggregate_scaling(runs)
        self.assertEqual(aggregate["association"]["100"]["median"], 15.0)
        self.assertEqual(aggregate["scheduler"]["240"]["median"], 36.0)


if __name__ == "__main__":
    unittest.main()
