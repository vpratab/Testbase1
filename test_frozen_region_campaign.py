import unittest

import numpy as np

from frozen_region_campaign import forecast_errors
from run_experiments import MaritimeTrack


class FrozenRegionCampaignTests(unittest.TestCase):
    def test_forecast_metrics_use_supplied_frozen_parameters(self) -> None:
        positions = np.column_stack(
            (np.arange(30, dtype=float), np.zeros(30))
        )
        track = MaritimeTrack(
            positions=positions,
            cooperative=np.ones(30, dtype=bool),
            anomalous=False,
            anomaly_start=15,
            anomaly_type="nominal",
            domain="surface",
        )
        metrics = forecast_errors([track], window=3, gain=1.0, horizon=5)
        self.assertAlmostEqual(metrics["forecast_rmse_km"], 0.0)
        self.assertGreater(metrics["improvement_vs_hold_pct"], 99.0)


if __name__ == "__main__":
    unittest.main()
