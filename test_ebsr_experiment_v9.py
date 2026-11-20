"""Regression coverage for the saved experiment-to-EBSR integration."""
from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import main
from ebsr_adapter import EBSRAdapterError, build_assessment, replay_assessment
from tools.build_ebsr_experiment_v9 import OUTPUT_PATH, build_bundle, load, sha256


class ExperimentV9Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = load(OUTPUT_PATH)
        cls.report = build_assessment(cls.bundle)
        cls.results = {result["scenario_id"]: result for result in cls.report["scenario_results"]}

    def result(self, arm, target):
        number = 1 if target == "MOSQUITTO" else 2
        return self.results[f"EXP{number}-12546-{arm}-{target}"]

    def conditions(self, arm, target):
        path = self.result(arm, target)["paths"][0]
        return [
            {
                variable: self.report["propositions"][pid]["status"]
                for variable, pid in step["condition_proposition_ids"].items()
            }
            for step in path["transitions"]
        ]

    def test_builder_reproduces_checked_in_bundle(self):
        self.assertEqual(build_bundle(), self.bundle)

    def test_withholding_only_disproves_capability_on_broker_step(self):
        direct, = self.conditions("CONTROL", "MOSQUITTO")
        first, downstream = self.conditions("CONTROL", "INFLUX")
        self.assertEqual((direct["K"], direct["Y"]), ("F", "T"))
        self.assertEqual((first["K"], first["Y"]), ("F", "U"))
        self.assertEqual((downstream["K"], downstream["Y"]), ("U", "U"))

    def test_bounded_target_absence_and_provenance(self):
        readback = load(Path(self.bundle["evidence_provenance"]["readback_verification"]))
        for target in ("DITTO", "INFLUX"):
            with self.subTest(target=target):
                result = self.result("CONTROL", target)
                self.assertEqual(result["paths"][0]["target_impact"]["I"]["status"], "F")
                self.assertEqual(result["feasibility_envelope"], [0.0, 0.0])
        item = next(
            item for item in self.bundle["evidence"]
            if item["proposition_id"] == "target.2018_12546.exp2.control.influxdb.I"
        )
        self.assertEqual(item["observation_window_utc"], readback["control_window_support"]["window"])
        self.assertEqual(item["run_marker"], readback["control_retained_marker"]["run_marker"])
        self.assertEqual(item["supporting_artifact_sha256"], sha256(Path(item["supporting_artifact"])))

    def test_confirmed_storage_with_unresolved_cve_free_gates(self):
        downstream = self.conditions("VULNERABLE", "INFLUX")[1]
        self.assertEqual((downstream["A"], downstream["G"], downstream["K"], downstream["Y"]),
                         ("U", "U", "T", "T"))
        result = self.result("VULNERABLE", "INFLUX")
        self.assertEqual(result["feasibility_envelope"], [0.0, 0.7294117647058823])
        self.assertEqual(result["paths"][0]["target_impact"]["I"]["status"], "UNQUANTIFIED")

    def test_reporting_is_path_scoped(self):
        direct, = self.result("VULNERABLE", "MOSQUITTO")["reproduction_scope"]
        self.assertEqual(direct["downstream_targets"], [])
        self.assertEqual(direct["downstream_cve_specific_testing"], "NOT_APPLICABLE")
        for arm, expected in (
            ("VULNERABLE", "CVE_EFFECT_OBSERVED"),
            ("CONTROL", "UPSTREAM_WITHHELD_NO_TARGET_EFFECT_OBSERVED"),
        ):
            ditto, = self.result(arm, "DITTO")["reproduction_scope"]
            influx, = self.result(arm, "INFLUX")["reproduction_scope"]
            self.assertEqual(ditto["downstream_cve_specific_testing"], expected)
            self.assertEqual(len(ditto["downstream_targets"]), 1)
            self.assertEqual({t["cve_specific_testing"] for t in influx["downstream_targets"]}, {expected})
            self.assertEqual(len(influx["downstream_targets"]), 2)

    def test_replay_from_serialized_report_retains_results_and_scope(self):
        replay = replay_assessment(json.loads(json.dumps(self.report)))
        for field in ("scenario_results", "propositions", "component_profiles"):
            self.assertEqual(self.report[field], replay[field])

    def test_live_stage_rejects_same_product_and_shared_endpoint_overlays(self):
        for deployment, component, version in (
            ("mosquitto-vuln-lab", "mosquitto", "1.5.5"),
            ("mosquitto-lab", "mosquitto", "2.1.2"),
            ("influxdb-lab", "influxdb", "2.7.11"),
        ):
            with self.subTest(deployment=deployment):
                baseline = {
                    "deployment_id": deployment,
                    "component_id": component,
                    "version": version,
                }
                with self.assertRaisesRegex(EBSRAdapterError, "offline evaluation"):
                    main.run_ebsr_stage(self.bundle, baseline)

    def test_live_cli_rejects_experiment_before_discovery(self):
        error_output = io.StringIO()
        with patch.object(main, "get_available_software") as discover:
            with redirect_stderr(error_output), self.assertRaises(SystemExit) as exit_info:
                main.run_cli(["--ebsr-scenarios", str(OUTPUT_PATH)])
        self.assertEqual(exit_info.exception.code, 2)
        self.assertIn("tools/run_ebsr_input.py", error_output.getvalue())
        discover.assert_not_called()
