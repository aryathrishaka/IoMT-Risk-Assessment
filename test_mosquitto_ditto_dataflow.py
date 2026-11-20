"""Focused offline tests for Mosquitto-to-Ditto experiment evidence."""

from pathlib import Path
import sys
import unittest

import requests


ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from run_mosquitto_ditto_dataflow import (  # noqa: E402
    correlate_broker_logs,
    evaluate_ditto_receipt,
    restore_connection_to_closed,
    summarize_experiment_and_cleanup,
)


TOPIC = "iomt/vuln-test"
CLIENT_ID = "iomt-df-publisher-current"


def metric_snapshot(
    consumed=0,
    mapped=0,
    topic_consumed=0,
    topic_mapped=0,
    outbound=0,
):
    return {
        "connectionMetrics": {
            "inbound": {
                "consumed": {
                    "success": {"PT1M": consumed}
                },
                "mapped": {
                    "success": {"PT1M": mapped}
                },
            },
            "outbound": {
                "dispatched": {
                    "success": {"PT1M": outbound}
                }
            },
        },
        "sourceMetrics": {
            "addressMetrics": {
                TOPIC: {
                    "consumed": {
                        "success": {"PT1M": topic_consumed}
                    },
                    "mapped": {
                        "success": {"PT1M": topic_mapped}
                    },
                }
            }
        },
    }


class DataFlowEvidenceTests(unittest.TestCase):

    def test_historical_and_wrong_client_logs_are_excluded(self):
        logs = [
            (
                "2026-11-17T09:59:59Z  Received PUBLISH from "
                f"{CLIENT_ID} on {TOPIC}"
            ),
            (
                "2026-11-17T10:00:06Z  Received PUBLISH from "
                f"historical-client on {TOPIC}"
            ),
            (
                "2026-11-17T10:00:06Z  Received PUBLISH from "
                f"{CLIENT_ID} on other/topic"
            ),
            (
                "2026-11-17T10:00:06Z  Received PUBLISH from "
                f"{CLIENT_ID} on {TOPIC}"
            ),
            (
                "2026-11-17T10:00:06Z  Sending PUBLISH to "
                f"ditto-client on {TOPIC}"
            ),
        ]

        correlated = correlate_broker_logs(
            logs,
            "2026-11-17T10:00:00Z",
            TOPIC,
            CLIENT_ID,
        )

        self.assertEqual(len(correlated["received"]), 1)
        self.assertIn(CLIENT_ID, correlated["received"][0])
        self.assertEqual(len(correlated["delivered"]), 1)

    def test_unrelated_metrics_change_is_not_receipt(self):
        before = metric_snapshot()
        after = metric_snapshot(outbound=5)

        result = evaluate_ditto_receipt(
            before,
            after,
            TOPIC,
            "marker-current",
            "marker-current",
        )

        self.assertFalse(result["relevant_inbound_counters_increased"])
        self.assertTrue(result["marker_match"])
        self.assertFalse(result["verified"])

    def test_receipt_requires_relevant_counters_and_marker(self):
        before = metric_snapshot()
        after = metric_snapshot(
            consumed=1,
            mapped=1,
            topic_consumed=1,
            topic_mapped=1,
        )

        result = evaluate_ditto_receipt(
            before,
            after,
            TOPIC,
            "marker-current",
            "marker-current",
        )

        self.assertTrue(result["relevant_inbound_counters_increased"])
        self.assertTrue(result["marker_match"])
        self.assertTrue(result["verified"])

    def test_cleanup_failure_is_not_reported_as_completed(self):
        outcome = summarize_experiment_and_cleanup(
            "VALIDATED",
            {
                "connection": False,
                "field": False,
                "policy": True,
                "broker_acl": True,
                "broker_state": True,
            },
        )

        self.assertEqual(outcome["result"], "CLEANUP_FAILED")
        self.assertEqual(outcome["experiment_outcome"], "VALIDATED")
        self.assertEqual(outcome["cleanup_outcome"], "FAILED")
        self.assertNotEqual(outcome["exit_code"], 0)

    def test_timeout_can_still_verify_applied_connection_close(self):
        class TimeoutSession:
            def put(self, *args, **kwargs):
                raise requests.Timeout("response timed out")

        result = restore_connection_to_closed(
            TimeoutSession(),
            {
                "id": "connection-test",
                "connectionStatus": "open",
            },
            timeout_seconds=1,
            status_reader=lambda _session: {"liveStatus": "closed"},
        )

        self.assertTrue(result["verified"])
        self.assertIn("Timeout", result["request_error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
