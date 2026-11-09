"""Focused tests for architecture-stage relationship compatibility."""

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import main


EDGE = ["Mosquitto", "Eclipse Ditto"]


def assess_with(relationship):
    output = io.StringIO()

    with patch.object(
        main,
        "get_relationship",
        return_value=relationship
    ):
        with redirect_stdout(output):
            result = main.assess_propagation(EDGE)

    return result, output.getvalue()


class ArchitecturePropagationTests(unittest.TestCase):

    def test_current_unknown_relationship_does_not_crash(self):
        output = io.StringIO()

        with redirect_stdout(output):
            result = main.assess_propagation(EDGE)

        self.assertEqual(
            result["status"],
            "INSUFFICIENT_EVIDENCE"
        )
        self.assertIsNone(result["propagation_score"])
        self.assertIn("relationship status is UNKNOWN", output.getvalue())

    def test_missing_relationship_is_preserved_as_unknown_limitation(self):
        result, output = assess_with(None)

        self.assertEqual(
            result["status"],
            "INSUFFICIENT_EVIDENCE"
        )
        self.assertIsNone(result["propagation_score"])
        self.assertIn(
            "relationship evidence is unavailable",
            result["explanation"]
        )
        self.assertIn(
            "Propagation score: NOT CALCULATED",
            output
        )

    def test_unknown_status_never_produces_a_score(self):
        relationship = {
            "relationship_type": "data_flow",
            "status": "UNKNOWN",
            "evidence": [],
            "notes": "Evidence has not been established.",
            "reachability": "Direct",
            "authentication": "Weak",
            "authorization": "Weak",
            "dependency": "High"
        }

        with patch.object(
            main,
            "calculate_propagation_score"
        ) as scorer:
            result, _ = assess_with(relationship)

        scorer.assert_not_called()
        self.assertEqual(
            result["status"],
            "INSUFFICIENT_EVIDENCE"
        )
        self.assertIsNone(result["propagation_score"])

    def test_supported_relationship_without_factor_evidence_avoids_keyerror(self):
        relationship = {
            "relationship_type": "data_flow",
            "status": "SUPPORTED",
            "evidence": ["Connection observed."],
            "notes": "Relationship supported."
        }

        result, output = assess_with(relationship)

        self.assertEqual(
            result["status"],
            "INSUFFICIENT_EVIDENCE"
        )
        self.assertIsNone(result["propagation_score"])
        self.assertIn(
            "supported relationship lacks scoring evidence",
            result["explanation"]
        )
        self.assertIn(
            "Missing scoring evidence: "
            "reachability, authentication, authorization, dependency",
            output
        )

    def test_supported_relationship_preserves_existing_scoring(self):
        relationship = {
            "relationship_type": "data_flow",
            "status": "SUPPORTED",
            "evidence": ["Connection observed."],
            "notes": "Relationship supported.",
            "reachability": "Direct",
            "authentication": "Weak",
            "authorization": "Weak",
            "dependency": "High"
        }

        result, _ = assess_with(relationship)

        self.assertEqual(result["status"], "SUPPORTED")
        self.assertAlmostEqual(
            result["propagation_score"],
            0.36
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
