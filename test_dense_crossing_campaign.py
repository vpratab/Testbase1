import unittest

import numpy as np

from dense_crossing_campaign import (
    component_optimal_assignment,
    dense_hungarian_assignment,
    greedy_assignment,
)


class DenseCrossingCampaignTests(unittest.TestCase):
    def test_greedy_can_be_suboptimal(self) -> None:
        cost = np.array([[1.0, 2.0], [1.1, 100.0]])
        valid = np.ones_like(cost, dtype=bool)
        greedy = greedy_assignment(cost, valid)
        optimal = dense_hungarian_assignment(cost, valid)
        greedy_cost = sum(cost[row, column] for row, column in greedy)
        optimal_cost = sum(cost[row, column] for row, column in optimal)
        self.assertGreater(greedy_cost, optimal_cost)

    def test_component_method_matches_global_on_disconnected_graph(self) -> None:
        cost = np.array(
            [
                [1.0, 2.0, 99.0, 99.0],
                [1.1, 8.0, 99.0, 99.0],
                [99.0, 99.0, 2.0, 1.0],
                [99.0, 99.0, 9.0, 1.1],
            ]
        )
        valid = cost < 90.0
        component, metadata = component_optimal_assignment(cost, valid)
        global_assignment = dense_hungarian_assignment(cost, valid)
        self.assertEqual(component, global_assignment)
        self.assertEqual(metadata["largest_component"], 2)
        self.assertEqual(metadata["capped_components"], 0)

    def test_component_cap_is_explicit(self) -> None:
        cost = np.ones((4, 4))
        valid = np.ones_like(cost, dtype=bool)
        _, metadata = component_optimal_assignment(
            cost,
            valid,
            maximum_component=2,
        )
        self.assertEqual(metadata["capped_components"], 1)


if __name__ == "__main__":
    unittest.main()
