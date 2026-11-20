"""Offline tests for Experiment 2 CSV readback verification."""

from datetime import datetime, timezone
import sys
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))

from verify_cve_2018_12546_downstream_readback import (  # noqa: E402
    next_nanosecond,
    point_time_from_ns,
    row_matches,
)


class ReadbackVerificationTests(unittest.TestCase):
    def test_row_match_requires_exact_identity(self):
        row = {
            "time": "2026-11-18T20:10:26.0464382Z",
            "value": 42.75,
            "run_marker": "MARKER",
            "thing_id": "iomt:test",
        }

        self.assertTrue(
            row_matches(
                row,
                thing_id="iomt:test",
                marker="MARKER",
                value=42.75,
            )
        )
        self.assertFalse(
            row_matches(
                row,
                thing_id="iomt:other",
                marker="MARKER",
                value=42.75,
            )
        )

    def test_next_nanosecond_moves_stop_past_last_row(self):
        original = "2026-11-18T20:11:45.7834545Z"
        following = next_nanosecond(original)

        self.assertGreater(following, original)

    def test_point_time_conversion_preserves_microsecond_precision(self):
        converted = point_time_from_ns(1795032626222226100)

        self.assertEqual(
            converted,
            "2026-11-18T20:10:26.222226Z",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
