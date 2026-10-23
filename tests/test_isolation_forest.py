import unittest

from src.isolation_forest_experiment import SKLEARN_AVAILABLE


@unittest.skipUnless(SKLEARN_AVAILABLE, "scikit-learn not installed (see requirements-ml.txt)")
class TestIsolationForest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from src.ai_anomaly import LoginRecord, generate_synthetic_logins
        from src.isolation_forest_experiment import IsolationForestDetector
        cls.LoginRecord = LoginRecord
        labelled = generate_synthetic_logins()
        normal = [r for r, bad in labelled if not bad]
        cls.detector = IsolationForestDetector().fit(normal)

    def test_normal_login_is_not_anomalous(self):
        result = self.detector.assess(self.LoginRecord("IN", "Android phone", 11, 0))
        self.assertFalse(result.is_anomalous)

    def test_foreign_night_login_is_anomalous(self):
        result = self.detector.assess(self.LoginRecord("RU", "Unknown Linux", 2, 4))
        self.assertTrue(result.is_anomalous)
        self.assertTrue(result.reasons)

    def test_experiment_reports_both_detectors(self):
        from src.isolation_forest_experiment import run_experiment
        results = run_experiment()
        self.assertIn("statistical_detector", results)
        self.assertIn("isolation_forest", results)
        self.assertGreater(results["isolation_forest"]["accuracy"], 0.8)


if __name__ == "__main__":
    unittest.main()
