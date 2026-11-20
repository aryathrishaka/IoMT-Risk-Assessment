"""Offline tests for the CVE-2018-12546 retained-message experiment."""

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "scripts"))

from run_cve_2018_12546_experiment import (  # noqa: E402
    CONTROL,
    VULNERABLE,
    broker_configuration,
    classify_arm,
    cleanup_assessment,
    compare_arms,
    find_denial_log,
    find_reload_log,
    legacy_password_line,
    verify_legacy_password_line,
)


class Cve201812546ExperimentTests(unittest.TestCase):
    def test_legacy_password_hash_round_trip(self):
        line = legacy_password_line(
            "experiment-publisher",
            "private-test-value",
            bytes.fromhex("00112233445566778899aabb"),
        )

        self.assertTrue(
            verify_legacy_password_line(
                line,
                "experiment-publisher",
                "private-test-value",
            )
        )
        self.assertFalse(
            verify_legacy_password_line(
                line,
                "experiment-publisher",
                "different-test-value",
            )
        )
        self.assertNotIn("private-test-value", line)

    def test_configuration_difference_is_explicit(self):
        vulnerable_config = broker_configuration(
            VULNERABLE["check_retain_source"]
        )
        control_config = broker_configuration(
            CONTROL["check_retain_source"]
        )

        self.assertNotIn("check_retain_source", vulnerable_config)
        self.assertIn("check_retain_source true", control_config)
        self.assertIn("protocol mqtt", vulnerable_config)
        self.assertIn("allow_anonymous false", vulnerable_config)

    def test_vulnerable_requires_delivery_and_enforced_revocation(self):
        result = classify_arm(
            VULNERABLE,
            runtime_version="1.5.5",
            auth_rejected_bad_password=True,
            initial_marker_delivered=True,
            revocation_enforced=True,
            stale_marker_delivered=True,
            replacement_marker_delivered=True,
        )

        self.assertEqual(result["outcome"], "CVE_BEHAVIOUR_OBSERVED")

    def test_puback_without_enforced_revocation_is_inconclusive(self):
        result = classify_arm(
            VULNERABLE,
            runtime_version="1.5.5",
            auth_rejected_bad_password=True,
            initial_marker_delivered=True,
            revocation_enforced=False,
            stale_marker_delivered=True,
            replacement_marker_delivered=True,
        )

        self.assertEqual(result["outcome"], "INCONCLUSIVE")

    def test_control_requires_withheld_marker_and_subscriber_access(self):
        result = classify_arm(
            CONTROL,
            runtime_version="2.1.2",
            auth_rejected_bad_password=True,
            initial_marker_delivered=True,
            revocation_enforced=True,
            stale_marker_delivered=False,
            replacement_marker_delivered=True,
        )

        self.assertEqual(result["outcome"], "CONTROL_BEHAVIOUR_OBSERVED")

    def test_control_delivery_is_not_reported_as_mitigated(self):
        result = classify_arm(
            CONTROL,
            runtime_version="2.1.2",
            auth_rejected_bad_password=True,
            initial_marker_delivered=True,
            revocation_enforced=True,
            stale_marker_delivered=True,
            replacement_marker_delivered=True,
        )

        self.assertEqual(result["outcome"], "UNEXPECTED_DELIVERY")

    def test_paired_comparison_does_not_infer_target_impact(self):
        comparison = compare_arms(
            {
                "assessment": {
                    "outcome": "CVE_BEHAVIOUR_OBSERVED"
                }
            },
            {
                "assessment": {
                    "outcome": "CONTROL_BEHAVIOUR_OBSERVED"
                }
            },
        )

        self.assertTrue(
            comparison["supports_cve_broker_behaviour_reproduction"]
        )
        self.assertIn(
            "target confidentiality, integrity or availability magnitude",
            comparison["does_not_establish"],
        )

    def test_historical_or_wrong_client_denial_is_excluded(self):
        lines = [
            (
                "2026-11-19T09:59:59Z Denied PUBLISH from "
                "current-client on iomt/test"
            ),
            (
                "2026-11-19T10:00:05Z Denied PUBLISH from "
                "historical-client on iomt/test"
            ),
            (
                "2026-11-19T10:00:05Z Denied PUBLISH from "
                "current-client on other/topic"
            ),
            (
                "2026-11-19T10:00:05Z Denied PUBLISH from "
                "current-client on iomt/test"
            ),
        ]

        matches = find_denial_log(
            lines,
            "2026-11-19T10:00:00Z",
            "iomt/test",
            "current-client",
        )

        self.assertEqual(len(matches), 1)

    def test_historical_reload_log_is_excluded(self):
        lines = [
            "2026-11-19T09:59:59Z Reloading config.",
            "2026-11-19T10:00:05Z Reloading config.",
        ]

        self.assertTrue(
            find_reload_log(lines, "2026-11-19T10:00:00Z")
        )
        self.assertFalse(
            find_reload_log(
                lines[:1],
                "2026-11-19T10:00:00Z",
            )
        )

    def test_cleanup_failure_has_nonzero_exit(self):
        result = cleanup_assessment(
            {
                "vulnerable_removed": True,
                "control_removed": False,
                "network_removed": True,
            }
        )

        self.assertEqual(result["outcome"], "FAILED")
        self.assertNotEqual(result["exit_code"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
