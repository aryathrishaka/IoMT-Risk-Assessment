"""Offline tests for the experiment-scoped CVE-2018-12546 EBSR bundle."""

import hashlib
import json
from pathlib import Path
import unittest

from ebsr_adapter import (
    build_assessment,
    load_input,
    replay_assessment,
)


ROOT = Path(__file__).resolve().parent
V7_PATH = ROOT / "scenarios" / "ebsr_mosquitto_12546_12550_12551_v7.json"
V8_PATH = ROOT / "scenarios" / "ebsr_cve_2018_12546_experiment_v8.json"
GENERATED_AT = "2026-11-18T20:56:03.791759Z"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class EbsrExperimentV8Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.v7_hash = sha256(V7_PATH)
        cls.ebsr_hash = sha256(ROOT / "ebsr.py")
        cls.document = load_input(V8_PATH)
        cls.report = build_assessment(
            cls.document,
            generated_at=GENERATED_AT,
        )
        cls.by_id = {
            result["scenario_id"]: result
            for result in cls.report["scenario_results"]
        }

    def scenario(self, scenario_id):
        return self.by_id[scenario_id]

    def path(self, scenario_id):
        return self.scenario(scenario_id)["paths"][0]

    def test_exact_temporary_deployments_are_bound(self):
        deployment_ids = {
            item["deployment_id"]
            for item in self.document["deployments"]
        }

        self.assertIn(
            "iomt-cve12546-down-vulnerable-00e1c6ba6c",
            deployment_ids,
        )
        self.assertIn(
            "iomt-cve12546-down-control-c4c0a63d22",
            deployment_ids,
        )
        self.assertIn("iomt-cve12546-vuln-b7c3ae4e", deployment_ids)
        self.assertIn("iomt-cve12546-control-28ae20e7", deployment_ids)
        self.assertNotIn("mosquitto-vuln-lab", deployment_ids)
        self.assertNotIn("mosquitto-lab", deployment_ids)

    def test_control_configuration_is_explicit(self):
        control = next(
            item
            for item in self.document["deployments"]
            if item["deployment_id"]
            == "iomt-cve12546-down-control-c4c0a63d22"
        )

        self.assertIn(
            "check_retain_source true",
            control["discovery_evidence"]["configuration"],
        )

    def test_six_scenarios_evaluate_without_errors(self):
        self.assertEqual(len(self.report["scenario_results"]), 6)
        self.assertEqual(self.report["scenario_errors"], [])
        self.assertEqual(self.report["input_errors"], [])

    def test_vulnerable_source_reproduction_is_independent(self):
        direct = self.path("EXP1-12546-VULNERABLE-MOSQUITTO")

        self.assertEqual(
            direct["reproduction_grades"],
            {"CVE-2018-12546": "INDEPENDENTLY_REPRODUCED"},
        )
        self.assertEqual(
            self.document["experiment_reproduction_scope"]["vulnerable"][
                "source_observation"
            ],
            "INDEPENDENTLY_REPRODUCED",
        )

    def test_control_path_remains_distinct(self):
        control = self.scenario("EXP2-12546-CONTROL-DITTO")
        path = control["paths"][0]
        states = path["transitions"][0]["condition_proposition_ids"]

        self.assertEqual(path["vulnerability_steps"], [])
        self.assertEqual(path["gate_status"], "F")
        self.assertEqual(
            self.report["propositions"][states["A"]]["status"],
            "F",
        )
        self.assertEqual(
            self.report["propositions"][states["K"]]["status"],
            "F",
        )
        self.assertEqual(
            self.report["propositions"][states["Y"]]["status"],
            "F",
        )
        self.assertEqual(control["status"], "ZERO")

    def test_cve_free_step_a_and_g_remain_unknown(self):
        for scenario_id in (
            "EXP2-12546-VULNERABLE-INFLUX",
            "EXP2-12546-CONTROL-INFLUX",
        ):
            path = self.path(scenario_id)
            states = path["transitions"][-1][
                "condition_proposition_ids"
            ]

            self.assertEqual(
                self.report["propositions"][states["A"]]["status"],
                "U",
            )
            self.assertEqual(
                self.report["propositions"][states["G"]]["status"],
                "U",
            )
            self.assertEqual(
                self.report["propositions"][states["B"]]["status"],
                "T",
            )

    def test_downstream_integrity_is_unquantified_without_ca_inference(self):
        for scenario_id in (
            "EXP2-12546-VULNERABLE-DITTO",
            "EXP2-12546-VULNERABLE-INFLUX",
        ):
            impact = self.path(scenario_id)["target_impact"]

            self.assertEqual(impact["I"]["status"], "UNQUANTIFIED")
            self.assertIsNone(impact["I"]["interval"])
            self.assertEqual(impact["C"]["status"], "U")
            self.assertEqual(impact["C"]["interval"], [0.0, 1.0])
            self.assertEqual(impact["A"]["status"], "U")
            self.assertEqual(impact["A"]["interval"], [0.0, 1.0])

    def test_control_retained_integrity_effect_is_absent(self):
        for scenario_id in (
            "EXP2-12546-CONTROL-DITTO",
            "EXP2-12546-CONTROL-INFLUX",
        ):
            impact = self.path(scenario_id)["target_impact"]

            self.assertEqual(impact["I"]["status"], "F")
            self.assertEqual(impact["I"]["interval"], [0.0, 0.0])
            self.assertEqual(impact["C"]["status"], "U")
            self.assertEqual(impact["A"]["status"], "U")

    def test_source_impact_is_not_copied_to_target(self):
        path = self.path("EXP2-12546-VULNERABLE-DITTO")
        source = path["source_impacts"][0]

        self.assertAlmostEqual(
            source["source_impact"]["channels"]["I"],
            0.56,
        )
        self.assertEqual(
            path["target_impact"]["I"]["status"],
            "UNQUANTIFIED",
        )
        self.assertIsNone(path["target_impact"]["I"]["interval"])

    def test_duplicate_rows_are_recorded_without_cause_claim(self):
        rows = self.document["readback_verification"]

        self.assertEqual(rows["vulnerable_row_count"], 2)
        self.assertEqual(rows["control_row_count"], 0)
        self.assertTrue(rows["duplicate_rows"])
        self.assertEqual(rows["duplicate_cause"], "UNKNOWN")

    def test_historical_manual_record_is_not_upgraded(self):
        decision = next(
            item
            for item in self.document["research_decisions"]
            if item["decision_id"] == "HISTORICAL_MANUAL_SEPARATE"
        )

        self.assertEqual(decision["status"], "PRESERVED")
        self.assertNotIn(
            "MANUALLY_OBSERVED",
            self.path("EXP2-12546-VULNERABLE-DITTO")[
                "reproduction_grades"
            ].values(),
        )

    def test_frozen_sources_are_unchanged(self):
        self.assertEqual(
            self.document["source_hashes"]["v7_scenario"],
            self.v7_hash,
        )
        self.assertEqual(
            self.document["source_hashes"]["ebsr"],
            self.ebsr_hash,
        )

    def test_offline_replay_is_consistent(self):
        replayed = replay_assessment(
            {
                **self.report,
                "adapter_input": self.document,
            },
            generated_at=GENERATED_AT,
        )

        self.assertEqual(
            replayed["scenario_results"],
            self.report["scenario_results"],
        )
        self.assertEqual(
            replayed["propositions"],
            self.report["propositions"],
        )
        self.assertEqual(
            replayed["component_profiles"],
            self.report["component_profiles"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
