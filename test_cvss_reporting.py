"""Regression tests for policy-aligned CVSS and reproduction reporting."""

import io
import json
from pathlib import Path
from contextlib import redirect_stdout
import unittest

from ebsr_adapter import (
    build_assessment,
    load_input,
    print_assessment_summary,
)
from nvd_api import extract_cve_information


ROOT = Path(__file__).resolve().parent
V7_PATH = ROOT / "scenarios" / "ebsr_mosquitto_12546_12550_12551_v7.json"
FIXED_TIME = "2026-11-17T00:00:00+00:00"


class CvssReportingTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.report = build_assessment(
            load_input(V7_PATH),
            generated_at=FIXED_TIME,
        )
        cls.records = {
            item["cve_id"]: item
            for item in cls.report["cvss_reporting"]
        }

    def scenario(self, scenario_id):
        return next(
            item
            for item in self.report["scenario_results"]
            if item["scenario_id"] == scenario_id
        )

    def test_saved_v7_discrepancies_use_nvd_primary(self):
        expected = {
            "CVE-2023-0809": (5.3, 5.8),
            "CVE-2023-3592": (7.5, 5.8),
        }
        for cve_id, (primary_score, alternative_score) in expected.items():
            record = self.records[cve_id]
            self.assertEqual(record["selected"]["version"], "3.1")
            self.assertEqual(record["selected"]["score"], primary_score)
            self.assertEqual(
                record["selected"]["source"],
                "nvd@nist.gov",
            )
            self.assertEqual(
                record["selected"]["source_type"],
                "Primary",
            )
            self.assertEqual(
                [
                    item["score"]
                    for item in record["score_differing_alternatives"]
                ],
                [alternative_score],
            )
            self.assertEqual(
                record["score_differing_alternatives"][0]["source"],
                "emo@eclipse.org",
            )
            self.assertEqual(
                record["score_differing_alternatives"][0]["source_type"],
                "Secondary",
            )

    def test_extract_cve_information_ignores_listed_secondary_first(self):
        item = {
            "cve": {
                "id": "CVE-2023-TEST",
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "type": "Secondary",
                            "source": "emo@eclipse.org",
                            "cvssData": {
                                "baseScore": 5.8,
                                "vectorString": (
                                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                                    "S:C/C:N/I:N/A:L"
                                ),
                            },
                        },
                        {
                            "type": "Primary",
                            "source": "nvd@nist.gov",
                            "cvssData": {
                                "baseScore": 5.3,
                                "vectorString": (
                                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                                    "S:U/C:N/I:N/A:L"
                                ),
                            },
                        },
                    ]
                },
            }
        }
        info = extract_cve_information(item)
        self.assertEqual(info["cvss_version"], "3.1")
        self.assertEqual(info["cvss_score"], 5.3)
        self.assertEqual(info["cvss_source"], "nvd@nist.gov")
        self.assertEqual(info["cvss_source_type"], "Primary")
        self.assertEqual(info["cvss_alternatives"][0]["score"], 5.8)

    def test_console_summary_shows_sources_and_alternatives(self):
        output = io.StringIO()
        with redirect_stdout(output):
            print_assessment_summary(self.report)
        text = output.getvalue()

        self.assertIn("CVSS Selection Summary", text)
        self.assertIn(
            "CVE-2023-0809 [AFFECTED]\n"
            "  Selected: CVSS 3.1 | 5.3 | nvd@nist.gov | Primary\n"
            "  Alternative: CVSS 3.1 | 5.8 | emo@eclipse.org | Secondary",
            text,
        )
        self.assertIn(
            "CVE-2023-3592 [AFFECTED]\n"
            "  Selected: CVSS 3.1 | 7.5 | nvd@nist.gov | Primary\n"
            "  Alternative: CVSS 3.1 | 5.8 | emo@eclipse.org | Secondary",
            text,
        )

    def test_12546_downstream_scope_is_separate_from_source_observation(self):
        ditto = self.scenario("RESEARCH-12546-DITTO")
        influx = self.scenario("RESEARCH-12546-INFLUX")

        for scenario, target_name in (
            (ditto, "Eclipse Ditto"),
            (influx, "InfluxDB"),
        ):
            scope = scenario["reproduction_scope"][0]
            self.assertEqual(
                scope["source_observation_label"],
                "MANUALLY_OBSERVED at Mosquitto",
            )
            target = next(
                item
                for item in scope["downstream_targets"]
                if item["target_component"] == target_name
            )
            self.assertEqual(
                target["cve_specific_testing"],
                "UNKNOWN",
            )
            self.assertEqual(
                target["normal_path_testing"],
                "VERIFIED_NORMAL_PATH_ONLY",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
