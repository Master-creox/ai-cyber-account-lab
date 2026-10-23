import unittest

from src.ai_anomaly import LoginRecord, evaluate, generate_synthetic_logins, train_default_detector


class TestAiAnomaly(unittest.TestCase):
    def setUp(self):
        self.detector = train_default_detector()

    def test_normal_login_is_not_anomalous(self):
        result = self.detector.assess(LoginRecord("IN", "Android phone", 11, 0))
        self.assertFalse(result.is_anomalous)

    def test_foreign_night_login_is_anomalous(self):
        result = self.detector.assess(LoginRecord("RU", "Unknown Linux", 2, 4))
        self.assertTrue(result.is_anomalous)
        self.assertTrue(result.reasons)

    def test_evaluation_beats_chance(self):
        summary = evaluate(self.detector, generate_synthetic_logins())
        self.assertGreater(summary["accuracy"], 0.8)


if __name__ == "__main__":
    unittest.main()
