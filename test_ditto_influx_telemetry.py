"""Offline tests for the isolated Ditto-to-InfluxDB telemetry writer."""

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parent
LAB_DIR = ROOT / "lab" / "ditto_influx_telemetry"
sys.path.insert(0, str(LAB_DIR))

from writer import (  # noqa: E402
    extract_values,
    format_line_protocol,
    parse_thing_id,
)


class DittoInfluxTelemetryTests(unittest.TestCase):

    def test_attribute_event_contains_required_values(self):
        payload = {
            "topic": (
                "iomt:ditto-influx-test/things/twin/events/modified"
            ),
            "path": "/attributes",
            "value": {
                "temperature": 39.25,
                "runMarker": "DI-TEST",
            },
        }
        self.assertEqual(
            parse_thing_id(payload),
            "iomt:ditto-influx-test",
        )
        self.assertEqual(
            extract_values(payload),
            (39.25, "DI-TEST"),
        )

    def test_full_thing_event_is_supported(self):
        payload = {
            "thingId": "iomt:ditto-influx-test",
            "path": "/",
            "value": {
                "attributes": {
                    "temperature": 38.5,
                    "runMarker": "DI-FULL",
                }
            },
        }
        self.assertEqual(
            extract_values(payload),
            (38.5, "DI-FULL"),
        )

    def test_http_push_thing_header_is_supported(self):
        payload = {
            "topic": "_/_/things/twin/events/modified",
            "headers": {"thing-id": "iomt:ditto-influx-test"},
        }
        self.assertEqual(
            parse_thing_id(payload),
            "iomt:ditto-influx-test",
        )

    def test_http_push_slash_separator_is_normalized(self):
        payload = {
            "topic": (
                "iomt/ditto-influx-test/things/twin/events/modified"
            )
        }
        self.assertEqual(
            parse_thing_id(payload),
            "iomt:ditto-influx-test",
        )

    def test_line_protocol_escapes_tags(self):
        line = format_line_protocol(
            "iomt:device,one",
            "marker=one",
            39.25,
            123456789,
        )
        self.assertIn("thing_id=iomt:device\\,one", line)
        self.assertIn("run_marker=marker\\=one", line)
        self.assertIn("temperature=39.25 123456789", line)

    def test_connection_template_uses_ditto_event_target(self):
        connection = json.loads(
            (LAB_DIR / "connection.template.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(connection["connectionType"], "http-push")
        self.assertEqual(connection["sources"], [])
        target = connection["targets"][0]
        self.assertTrue(
            target["topics"][0].startswith("_/_/things/twin/events")
        )
        self.assertEqual(
            target["authorizationContext"],
            ["ditto:outbound-auth-subject"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
