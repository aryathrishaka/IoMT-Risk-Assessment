"""Offline tests for the CVE-2018-12546 downstream experiment."""

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "scripts"))

from run_cve_2018_12546_downstream_experiment import (  # noqa: E402
    BASELINE_MARKER,
    BASELINE_TEMPERATURE,
    cleanup_assessment,
    compare_outcomes,
    ditto_command_payload,
    normal_path_verified,
    redact_connection,
    thing_has_values,
)


class DownstreamExperimentTests(unittest.TestCase):
    def test_isolated_payload_targets_exact_thing_and_values(self):
        payload = ditto_command_payload(
            "iomt:experiment-1",
            42.75,
            "MARKER-1",
        )

        self.assertEqual(
            payload["topic"],
            "iomt/experiment-1/things/twin/commands/modify",
        )
        self.assertEqual(
            payload["value"],
            {"temperature": 42.75, "runMarker": "MARKER-1"},
        )

    def test_baseline_match_requires_both_fields(self):
        thing = {
            "attributes": {
                "temperature": BASELINE_TEMPERATURE,
                "runMarker": BASELINE_MARKER,
            }
        }

        self.assertTrue(
            thing_has_values(
                thing,
                BASELINE_TEMPERATURE,
                BASELINE_MARKER,
            )
        )
        self.assertFalse(
            thing_has_values(
                thing,
                42.75,
                BASELINE_MARKER,
            )
        )

    def test_normal_path_requires_thing_and_writer(self):
        thing = {
            "attributes": {"temperature": 41.25, "runMarker": "NORMAL"}
        }
        event = {
            "result": "WRITTEN",
            "thing_id": "iomt:test",
            "temperature": 41.25,
            "run_marker": "NORMAL",
            "influx_http_status": 204,
        }

        self.assertTrue(
            normal_path_verified(
                thing,
                event,
                {"status": "PENDING_USER_CONFIRMATION"},
                "iomt:test",
                "NORMAL",
            )
        )
        self.assertFalse(
            normal_path_verified(
                thing,
                None,
                {"status": "PENDING_USER_CONFIRMATION"},
                "iomt:test",
                "NORMAL",
            )
        )

    def test_vulnerable_policy_violation_is_classified(self):
        assessment = classify_for_test(
            arm_name="vulnerable",
            thing_changed=True,
            writer_event=True,
            influx_row=False,
        )

        self.assertEqual(assessment["outcome"], "POLICY_VIOLATION_OBSERVED")
        self.assertTrue(assessment["policy_violation"])

    def test_control_requires_withheld_effect_and_post_control(self):
        assessment = classify_for_test(
            arm_name="control",
            thing_changed=False,
            writer_event=False,
            influx_row=False,
        )

        self.assertEqual(assessment["outcome"], "POLICY_HELD")

    def test_control_effect_is_not_reported_as_held(self):
        assessment = classify_for_test(
            arm_name="control",
            thing_changed=True,
            writer_event=False,
            influx_row=False,
        )

        self.assertEqual(
            assessment["outcome"],
            "UNEXPECTED_CONTROL_POLICY_VIOLATION",
        )

    def test_failed_post_control_is_not_policy_held(self):
        from run_cve_2018_12546_downstream_experiment import (
            classify_downstream_outcome,
        )

        assessment = classify_downstream_outcome(
            arm_name="control",
            normal_path_ok=True,
            revoked_before_retained_delivery=True,
            retained_was_established=True,
            malicious_thing_changed=False,
            malicious_writer_event=False,
            malicious_influx_row=False,
            post_control_thing_changed=False,
            post_control_writer_event=False,
        )

        self.assertEqual(
            assessment["outcome"],
            "INCONCLUSIVE_POST_CONTROL_FAILED",
        )

    def test_thing_or_writer_effect_is_enough_for_policy_violation(self):
        thing_only = classify_for_test(
            arm_name="vulnerable",
            thing_changed=True,
            writer_event=False,
            influx_row=False,
        )
        writer_only = classify_for_test(
            arm_name="vulnerable",
            thing_changed=False,
            writer_event=True,
            influx_row=False,
        )

        self.assertTrue(thing_only["policy_violation"])
        self.assertTrue(writer_only["policy_violation"])

    def test_paired_difference_does_not_imply_clinical_harm(self):
        comparison = compare_outcomes(
            {
                "assessment": {"outcome": "POLICY_VIOLATION_OBSERVED"},
                "cleanup": {"outcome": "VERIFIED"},
            },
            {
                "assessment": {"outcome": "POLICY_HELD"},
                "cleanup": {"outcome": "VERIFIED"},
            },
        )

        self.assertEqual(
            comparison["outcome"],
            "PAIRED_DOWNSTREAM_DIFFERENCE_OBSERVED",
        )
        self.assertIn("clinical", comparison["assessment_boundary"])

    def test_connection_redaction_removes_uri_credentials(self):
        redacted = redact_connection(
            {
                "uri": "tcp://user:secret@temporary-broker:1883",
                "connectionType": "mqtt",
            }
        )

        self.assertEqual(
            redacted["uri"],
            "tcp://temporary-broker:1883",
        )
        self.assertNotIn("secret", redacted["uri"])

    def test_cleanup_failure_is_not_silently_successful(self):
        result = cleanup_assessment(
            {
                "thing_deleted": True,
                "policy_deleted": True,
                "temporary_broker_removed": False,
                "runtime_removed": True,
            }
        )

        self.assertEqual(result["outcome"], "FAILED")
        self.assertNotEqual(result["exit_code"], 0)


def classify_for_test(
    *,
    arm_name,
    thing_changed,
    writer_event,
    influx_row,
):
    from run_cve_2018_12546_downstream_experiment import (
        classify_downstream_outcome,
    )

    return classify_downstream_outcome(
        arm_name=arm_name,
        normal_path_ok=True,
        revoked_before_retained_delivery=True,
        retained_was_established=True,
        malicious_thing_changed=thing_changed,
        malicious_writer_event=writer_event,
        malicious_influx_row=influx_row,
        post_control_thing_changed=True,
        post_control_writer_event=True,
    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
