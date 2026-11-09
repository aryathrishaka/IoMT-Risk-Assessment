"""Tests for canonical applicability identity and structured CPE evidence."""

import json
import unittest

from applicability import (
    AFFECTED,
    NOT_AFFECTED,
    UNKNOWN,
    evaluate_applicability,
)
from testutil import cpe, config, cve, node, simple


LINUX = cpe(
    "linux_kernel",
    vendor="linux",
    part="o",
    vulnerable=False
)
MOSQUITTO = cpe(
    "mosquitto",
    versionStartIncluding="1.0",
    versionEndExcluding="2.0"
)
OTHER_APP = cpe(
    "helper",
    vendor="example",
    vulnerable=False,
    versionEndExcluding="2.0"
)


class ApplicabilityProvenanceTests(unittest.TestCase):

    def test_canonical_id_and_display_name_are_equivalent(self):
        record = simple("CVE-1", MOSQUITTO)

        canonical = evaluate_applicability(
            record,
            "mosquitto",
            "1.5.5"
        )
        display = evaluate_applicability(
            record,
            "Mosquitto",
            "1.5.5"
        )

        self.assertEqual(canonical["status"], AFFECTED)
        self.assertEqual(display["status"], AFFECTED)
        self.assertEqual(
            canonical["component"]["canonical_id"],
            "mosquitto"
        )
        self.assertEqual(
            canonical["component"]["cpe_vendor"],
            "eclipse"
        )
        self.assertEqual(
            canonical["component"]["cpe_product"],
            "mosquitto"
        )

    def test_version_boundaries_and_cpe_criteria_are_retained(self):
        result = evaluate_applicability(
            simple("CVE-2", MOSQUITTO),
            "mosquitto",
            "1.5.5"
        )
        root = result["configurations"][0]["decision_tree"]
        leaf = root["child_results"][0]["child_results"][0]

        self.assertEqual(
            leaf["criteria"],
            MOSQUITTO["criteria"]
        )
        self.assertEqual(
            leaf["constraints"]["start_including"],
            "1.0"
        )
        self.assertEqual(
            leaf["constraints"]["end_excluding"],
            "2.0"
        )
        self.assertEqual(leaf["status"], "TRUE")

    def test_nested_and_or_not_decisions_are_serialisable(self):
        record = cve(
            "CVE-3",
            [
                config(
                    node(MOSQUITTO, LINUX, operator="AND"),
                    node(
                        nodes=[
                            node(OTHER_APP, operator="OR")
                        ],
                        operator="AND",
                        negate=True
                    ),
                    operator="AND"
                )
            ]
        )

        result = evaluate_applicability(
            record,
            "mosquitto",
            "1.5.5"
        )
        root = result["configurations"][0]["decision_tree"]

        def nodes(node):
            yield node

            for child in node.get("child_results", []):
                if child.get("kind") == "node":
                    yield from nodes(child)

        descendant_nodes = list(nodes(root))

        self.assertEqual(result["status"], UNKNOWN)
        self.assertEqual(root["operator"], "AND")
        self.assertIn(
            "OR",
            {node["operator"] for node in descendant_nodes}
        )
        self.assertTrue(
            any(node["negated"] for node in descendant_nodes)
        )
        self.assertTrue(
            any(node["status"] == "UNKNOWN" for node in descendant_nodes)
        )
        json.dumps(result)

    def test_not_affected_reason_and_tree_are_retained(self):
        result = evaluate_applicability(
            simple("CVE-4", MOSQUITTO),
            "mosquitto",
            "2.1.2"
        )

        self.assertEqual(result["status"], NOT_AFFECTED)
        self.assertEqual(
            result["configurations"][0]["result"],
            "FALSE"
        )
        self.assertIn(
            "does not satisfy",
            result["reason"]
        )

    def test_unknown_platform_reason_is_explicit(self):
        result = evaluate_applicability(
            simple("CVE-5", MOSQUITTO),
            "mosquitto",
            "1.5.5",
            environment={}
        )

        self.assertEqual(result["status"], AFFECTED)
        self.assertEqual(
            result["environment_source"],
            "caller"
        )

        record = cve(
            "CVE-6",
            [
                config(
                    node(MOSQUITTO, LINUX, operator="AND")
                )
            ]
        )
        platform_unknown = evaluate_applicability(
            record,
            "mosquitto",
            "1.5.5",
            environment={}
        )

        self.assertEqual(platform_unknown["status"], UNKNOWN)
        self.assertIn(
            "Operating-system condition",
            json.dumps(platform_unknown)
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
