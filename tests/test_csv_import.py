import csv
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from src.cli import load_logins_csv, main


def _write_csv(rows, header=("country", "device", "hour", "failed_attempts", "is_anomalous")):
    fh = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="")
    writer = csv.writer(fh)
    writer.writerow(header)
    writer.writerows(rows)
    fh.close()
    return fh.name


class TestCsvImport(unittest.TestCase):
    def test_loads_rows_with_labels(self):
        path = _write_csv([("IN", "Android phone", 11, 0, 0),
                           ("RU", "Unknown Linux", 2, 4, 1)])
        try:
            rows = load_logins_csv(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][0].country, "IN")
        self.assertFalse(rows[0][1])
        self.assertTrue(rows[1][1])

    def test_missing_columns_raise_friendly_error(self):
        path = _write_csv([("IN", 11)], header=("country", "hour"))
        try:
            with self.assertRaises(ValueError):
                load_logins_csv(path)
        finally:
            os.unlink(path)

    def test_bad_hour_raises_friendly_error(self):
        path = _write_csv([("IN", "Android phone", "late", 0, 0)])
        try:
            with self.assertRaises(ValueError):
                load_logins_csv(path)
        finally:
            os.unlink(path)

    def test_analyze_csv_cli_flags_foreign_night_login(self):
        path = _write_csv([("IN", "Android phone", 11, 0, 0),
                           ("RU", "Unknown Linux", 2, 4, 1)])
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                code = main(["analyze-csv", path])
        finally:
            os.unlink(path)
        text = out.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("Analysed 2 logins", text)
        self.assertIn("ANOMALOUS", text)
        self.assertIn("accuracy vs labels", text)


if __name__ == "__main__":
    unittest.main()
