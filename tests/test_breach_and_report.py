import unittest

from src.breach_pattern import is_common_password
from src.report import run_all_checks


class TestBreachPattern(unittest.TestCase):
    def test_common_password_detected_by_hash(self):
        self.assertTrue(is_common_password("password"))

    def test_unique_passphrase_not_flagged(self):
        self.assertFalse(is_common_password("Correct horse battery staple 42!"))


class TestReport(unittest.TestCase):
    def test_risky_inputs_flag_high_risk(self):
        report = run_all_checks("password", "http://192.168.1.10/login@x.example.com",
                                country="RU", device="Unknown Linux", hour=2, failed_attempts=4)
        self.assertEqual(report["overall"], "HIGH RISK")

    def test_normal_inputs_are_ok(self):
        report = run_all_checks("Correct horse battery staple 42!", "https://github.com/Master-creox",
                                country="IN", device="Android phone", hour=11)
        self.assertEqual(report["overall"], "OK")


if __name__ == "__main__":
    unittest.main()
