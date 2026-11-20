"""Integration tests for the first evidence-backed EBSR research set."""

from copy import deepcopy
import json
import tempfile
import unittest
from pathlib import Path

from ebsr_adapter import (
    build_assessment,
    load_input,
    replay_assessment,
    save_assessment,
)


SCENARIO_PATH = Path(
    "scenarios/ebsr_mosquitto_12546_12551_v1.json"
)
SCENARIO_V2_PATH = Path(
    "scenarios/ebsr_mosquitto_12546_12551_v2.json"
)
SCENARIO_V3_PATH = Path(
    "scenarios/ebsr_mosquitto_12546_12551_v3.json"
)
SCENARIO_V4_PATH = Path(
    "scenarios/ebsr_mosquitto_12546_12551_v4.json"
)
SCENARIO_V5_PATH = Path(
    "scenarios/ebsr_mosquitto_12546_12551_v5.json"
)
SCENARIO_V6_PATH = Path(
    "scenarios/ebsr_mosquitto_12546_12551_v6.json"
)
SCENARIO_V7_PATH = Path(
    "scenarios/ebsr_mosquitto_12546_12550_12551_v7.json"
)
FIXED_TIME = "2026-11-10T18:30:00+00:00"


class ResearchScenarioTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.document = load_input(SCENARIO_PATH)
        cls.report = build_assessment(
            cls.document,
            generated_at=FIXED_TIME,
        )

    def scenario(self, scenario_id):
        return next(
            result
            for result in self.report["scenario_results"]
            if result["scenario_id"] == scenario_id
        )

    def test_saved_real_report_counts_are_preserved(self):
        assessment = self.document["cve_assessments"][0]

        self.assertEqual(assessment["retrieval"]["received"], 37)
        self.assertEqual(len(assessment["affected"]), 10)
        self.assertEqual(len(assessment["not_affected"]), 23)
        self.assertEqual(len(assessment["unknown"]), 4)
        self.assertEqual(
            self.report["applicability_accounting"][0]["counts"],
            {
                "retrieved": 37,
                "affected": 10,
                "not_affected": 23,
                "unknown": 4,
                "skipped_or_invalid_status": 0,
            },
        )

    def test_scenario_bundle_uses_exact_deployment_ids(self):
        deployment_ids = {
            deployment["deployment_id"]
            for deployment in self.report["input_evidence"][
                "deployments"
            ]
        }

        self.assertEqual(
            deployment_ids,
            {
                "mosquitto-vuln-lab",
                "docker",
                "influxdb-lab",
            },
        )

    def test_six_scenarios_cover_all_three_targets(self):
        self.assertEqual(
            {
                result["scenario_id"]
                for result in self.report["scenario_results"]
            },
            {
                "RESEARCH-12546-MOSQUITTO",
                "RESEARCH-12546-DITTO",
                "RESEARCH-12546-INFLUX",
                "RESEARCH-12551-MOSQUITTO",
                "RESEARCH-12551-DITTO",
                "RESEARCH-12551-INFLUX",
            },
        )
        self.assertEqual(
            {
                result["target_component"]
                for result in self.report["scenario_results"]
            },
            {
                "mosquitto-vuln-lab",
                "docker",
                "influxdb-lab",
            },
        )

    def test_cves_bind_to_source_deployment_and_ordered_transitions(self):
        result = self.scenario("RESEARCH-12546-INFLUX")
        path = result["paths"][0]

        self.assertEqual(
            path["cve_deployment_ids"],
            {"CVE-2018-12546": "mosquitto-vuln-lab"},
        )
        self.assertEqual(
            [
                transition["source_deployment_id"]
                for transition in path["transitions"]
            ],
            ["mosquitto-vuln-lab", "docker"],
        )
        self.assertEqual(
            path["transitions"][1]["cve_ids"],
            [],
        )

    def test_12546_v31_source_impact_is_retained_separately(self):
        path = self.scenario(
            "RESEARCH-12546-MOSQUITTO"
        )["paths"][0]
        source = path["source_impacts"][0]

        self.assertEqual(source["cvss_version"], "3.1")
        self.assertTrue(source["ebsr_index_supported"])
        self.assertAlmostEqual(
            source["source_impact"]["channels"]["I"],
            0.56,
        )
        self.assertEqual(
            path["target_impact"]["I"]["status"],
            "UNQUANTIFIED",
        )
        self.assertIsNone(
            path["target_impact"]["I"]["interval"]
        )

    def test_12551_v30_vector_remains_unquantified(self):
        result = self.scenario(
            "RESEARCH-12551-MOSQUITTO"
        )
        path = result["paths"][0]
        source = path["source_impacts"][0]

        self.assertEqual(source["cvss_version"], "3.0")
        self.assertFalse(source["ebsr_index_supported"])
        self.assertIsNone(source["source_impact"])
        self.assertEqual(
            path["feasibility"]["status"],
            "UNQUANTIFIED",
        )
        self.assertIsNone(path["feasibility"]["interval"])
        self.assertEqual(result["status"], "UNQUANTIFIED")

    def test_downstream_target_values_are_not_copied(self):
        for scenario_id in (
            "RESEARCH-12546-DITTO",
            "RESEARCH-12546-INFLUX",
            "RESEARCH-12551-DITTO",
            "RESEARCH-12551-INFLUX",
        ):
            path = self.scenario(scenario_id)["paths"][0]

            for channel in ("C", "I", "A"):
                self.assertEqual(
                    path["target_impact"][channel]["status"],
                    "U",
                )
                self.assertEqual(
                    path["target_impact"][channel]["interval"],
                    [0.0, 1.0],
                )

    def test_uncovered_affected_and_unknown_cves_are_not_assessed(self):
        statuses = [
            record["applicability_status"]
            for record in self.report["not_assessed_cves"]
        ]

        self.assertEqual(statuses.count("AFFECTED"), 8)
        self.assertEqual(statuses.count("UNKNOWN"), 4)
        self.assertTrue(all(
            record["status"] == "NOT_ASSESSED"
            for record in self.report["not_assessed_cves"]
        ))

    def test_12546_reproduction_grade_remains_manual(self):
        result = self.scenario("RESEARCH-12546-DITTO")

        self.assertEqual(
            result["paths"][0]["reproduction_grades"],
            {"CVE-2018-12546": "MANUALLY_OBSERVED"},
        )

    def test_evidence_classes_distinguish_research_sources(self):
        classes = {
            item["evidence_class"]
            for item in self.document["evidence"]
        }

        self.assertIn("DOCUMENTED_VULNERABILITY_BEHAVIOUR", classes)
        self.assertIn("HISTORICAL_MANUAL_OBSERVATION", classes)
        self.assertIn("HISTORICAL_OBSERVATION", classes)
        self.assertIn("CURRENT_DEPLOYMENT_EVIDENCE", classes)
        self.assertIn("EVIDENCE_GAP", classes)
        self.assertNotIn("SYNTHETIC_TEST_FIXTURE", classes)

    def test_report_and_offline_replay_are_consistent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = save_assessment(
                self.report,
                output_dir=directory,
            )
            replayed = replay_assessment(
                path,
                generated_at=FIXED_TIME,
            )

        self.assertEqual(
            replayed["scenario_results"],
            self.report["scenario_results"],
        )
        self.assertEqual(
            replayed["component_profiles"],
            self.report["component_profiles"],
        )
        self.assertEqual(
            replayed["not_assessed_cves"],
            self.report["not_assessed_cves"],
        )

    def test_report_is_json_serialisable(self):
        encoded = json.dumps(self.report)

        self.assertIn(
            "CVE-2018-12546",
            encoded,
        )
        self.assertIn(
            "CVE-2018-12551",
            encoded,
        )


class ResearchScenarioV2Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.v1_document = load_input(SCENARIO_PATH)
        cls.v1_report = build_assessment(
            cls.v1_document,
            generated_at=FIXED_TIME,
        )
        cls.v2_document = load_input(SCENARIO_V2_PATH)
        cls.v2_report = build_assessment(
            cls.v2_document,
            generated_at=FIXED_TIME,
        )

    def influx_path(self, report, scenario_id):
        scenario = next(
            item
            for item in report["scenario_results"]
            if item["scenario_id"] == scenario_id
        )
        return scenario, scenario["paths"][0]

    def test_v2_influx_write_is_data_flow_without_cve(self):
        for scenario_id in (
            "RESEARCH-12546-INFLUX",
            "RESEARCH-12551-INFLUX",
        ):
            _, path = self.influx_path(
                self.v2_report,
                scenario_id,
            )
            transition = path["transitions"][1]

            self.assertEqual(
                transition["transition_type"],
                "DF",
            )
            self.assertEqual(transition["cve_ids"], [])
            relation = next(
                item
                for item in self.v2_document[
                    "architecture_evidence"
                ]
                if item["relationship_id"] == transition[
                    "relationship_id"
                ]
            )
            self.assertEqual(
                relation["transition_type"],
                "DF",
            )
            self.assertEqual(relation["status"], "UNKNOWN")

    def test_v2_step_conditions_reference_distinct_facts(self):
        _, path = self.influx_path(
            self.v2_report,
            "RESEARCH-12546-INFLUX",
        )
        conditions = path["transitions"][1][
            "condition_proposition_ids"
        ]

        self.assertEqual(
            conditions,
            {
                "A": "non_cve.ditto_to_influx.step_available",
                "G": "attacker.ditto_to_influx.capability_requirement",
                "H": "configuration.ditto_to_influx.receiver_controls",
                "B": "transition.ditto_to_influx.current",
                "K": "receiver.influxdb.processing_evidence",
                "Y": "consequence.influxdb.target_effect",
            },
        )
        self.assertEqual(
            len(set(conditions.values())),
            len(conditions),
        )

    def test_data_flow_evidence_alone_does_not_establish_other_facts(self):
        document = deepcopy(self.v2_document)

        relation = next(
            item
            for item in document["architecture_evidence"]
            if item["relationship_id"]
            == "relationship.ditto-to-influx"
        )
        relation["status"] = "SUPPORTED"
        relation["evidence"] = [
            "Synthetic test-only assertion that the data-flow relationship "
            "is established."
        ]

        flow = next(
            item
            for item in document["evidence"]
            if item["proposition_id"]
            == "transition.ditto_to_influx.current"
        )
        flow["status"] = "T"
        flow["evidence_class"] = "SYNTHETIC_TEST_FIXTURE"
        flow["evidence"] = [
            "Synthetic test-only assertion used to isolate relationship "
            "evidence."
        ]

        report = build_assessment(
            document,
            generated_at=FIXED_TIME,
        )

        for scenario_id in (
            "RESEARCH-12546-INFLUX",
            "RESEARCH-12551-INFLUX",
        ):
            scenario, path = self.influx_path(
                report,
                scenario_id,
            )
            transitions = path["transitions"][1]
            condition_ids = transitions[
                "condition_proposition_ids"
            ]

            self.assertEqual(
                report["propositions"][condition_ids["B"]]["status"],
                "T",
            )
            for variable in ("A", "G", "H", "K", "Y"):
                self.assertEqual(
                    report["propositions"][
                        condition_ids[variable]
                    ]["status"],
                    "U",
                )
            self.assertEqual(path["gate_status"], "U")
            self.assertNotEqual(scenario["status"], "QUANTIFIED")
            for channel in ("C", "I", "A"):
                self.assertEqual(
                    path["target_impact"][channel]["status"],
                    "U",
                )

    def test_all_six_v2_results_preserve_v1_numerical_results(self):
        v1_by_id = {
            item["scenario_id"]: item
            for item in self.v1_report["scenario_results"]
        }
        v2_by_id = {
            item["scenario_id"]: item
            for item in self.v2_report["scenario_results"]
        }

        self.assertEqual(set(v1_by_id), set(v2_by_id))

        for scenario_id in v1_by_id:
            v1 = v1_by_id[scenario_id]
            v2 = v2_by_id[scenario_id]
            self.assertEqual(v1["status"], v2["status"])
            self.assertEqual(
                v1["feasibility_envelope"],
                v2["feasibility_envelope"],
            )
            self.assertEqual(
                v1["paths"][0]["target_impact"],
                v2["paths"][0]["target_impact"],
            )

            if scenario_id.endswith("-INFLUX"):
                self.assertEqual(
                    v1["paths"][0]["transition_types"],
                    ["DF", "LX"],
                )
                self.assertEqual(
                    v2["paths"][0]["transition_types"],
                    ["DF", "DF"],
                )
            else:
                self.assertEqual(
                    v1["paths"][0]["transition_types"],
                    v2["paths"][0]["transition_types"],
                )

    def test_v2_replay_is_consistent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = save_assessment(
                self.v2_report,
                output_dir=directory,
            )
            replayed = replay_assessment(
                path,
                generated_at=FIXED_TIME,
            )

        self.assertEqual(
            replayed["scenario_results"],
            self.v2_report["scenario_results"],
        )
        self.assertEqual(
            replayed["component_profiles"],
            self.v2_report["component_profiles"],
        )
        self.assertEqual(
            replayed["not_assessed_cves"],
            self.v2_report["not_assessed_cves"],
        )


class ResearchScenarioV3Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.v2_document = load_input(SCENARIO_V2_PATH)
        cls.v2_report = build_assessment(
            cls.v2_document,
            generated_at=FIXED_TIME,
        )
        cls.v3_document = load_input(SCENARIO_V3_PATH)
        cls.v3_report = build_assessment(
            cls.v3_document,
            generated_at=FIXED_TIME,
        )

    def scenario(self, scenario_id):
        return next(
            result
            for result in self.v3_report["scenario_results"]
            if result["scenario_id"] == scenario_id
        )

    def influx_path(self):
        return self.scenario(
            "RESEARCH-12546-INFLUX"
        )["paths"][0]

    def test_cve_free_step_keeps_undefined_a_and_g_unknown(self):
        path = self.influx_path()
        step = path["transitions"][1]
        conditions = step["condition_proposition_ids"]

        self.assertEqual(conditions["A"], "unresolved.cve_free_step.A_semantics")
        self.assertEqual(conditions["G"], "unresolved.cve_free_step.G_semantics")
        self.assertEqual(
            self.v3_report["propositions"][conditions["A"]]["status"],
            "U",
        )
        self.assertEqual(
            self.v3_report["propositions"][conditions["G"]]["status"],
            "U",
        )
        decisions = {
            item["decision_id"]: item["status"]
            for item in self.v3_document["research_decisions"]
        }
        self.assertEqual(
            decisions["CVE_FREE_STEP_A_G_UNDEFINED"],
            "UNDEFINED_IN_FROZEN_MATERIAL",
        )

    def test_cve_free_step_uses_h_k_y_for_their_frozen_meanings(self):
        step = self.influx_path()["transitions"][1]
        conditions = step["condition_proposition_ids"]

        self.assertEqual(
            conditions["H"],
            "deployment.ditto_to_influx.write_prerequisites",
        )
        self.assertEqual(
            conditions["B"],
            "transition.ditto_to_influx.current",
        )
        self.assertEqual(
            conditions["K"],
            "capability.ditto_to_influx.vulnerability_effect",
        )
        self.assertEqual(
            conditions["Y"],
            "receiver.influxdb.processing_and_controls",
        )
        self.assertEqual(step["transition_type"], "DF")
        self.assertEqual(step["cve_ids"], [])

    def test_first_hop_keeps_capability_and_receiver_processing_separate(self):
        path = self.influx_path()
        first = path["transitions"][0]["condition_proposition_ids"]
        second = path["transitions"][1]["condition_proposition_ids"]

        self.assertEqual(
            first["H"],
            "configuration.2018_12546.retained_message_and_acl",
        )
        self.assertEqual(
            first["K"],
            "capability.2018_12546.transition_to_ditto",
        )
        self.assertEqual(
            first["Y"],
            "receiver.ditto.2018_12546.processing_and_controls",
        )
        self.assertNotEqual(first["K"], first["Y"])
        self.assertEqual(
            path["target_impact"]["I"]["proposition_id"],
            "target.influx.12546.I",
        )
        self.assertNotIn(
            path["target_impact"]["I"]["proposition_id"],
            {first["K"], first["Y"], second["K"], second["Y"]},
        )

    def test_authorised_write_supports_b_but_not_other_conditions(self):
        document = deepcopy(self.v3_document)
        relation = next(
            item
            for item in document["architecture_evidence"]
            if item["relationship_id"]
            == "relationship.ditto-to-influx"
        )
        relation["status"] = "SUPPORTED"
        relation["evidence"] = [
            "Synthetic test-only authorised write observation."
        ]
        flow = next(
            item
            for item in document["evidence"]
            if item["proposition_id"]
            == "transition.ditto_to_influx.current"
        )
        flow["status"] = "T"
        flow["evidence_class"] = "SYNTHETIC_TEST_FIXTURE"
        flow["evidence"] = [
            "Synthetic test-only authorisation and write evidence."
        ]

        report = build_assessment(
            document,
            generated_at=FIXED_TIME,
        )
        scenario = next(
            item
            for item in report["scenario_results"]
            if item["scenario_id"] == "RESEARCH-12546-INFLUX"
        )
        path = scenario["paths"][0]
        conditions = path["transitions"][1][
            "condition_proposition_ids"
        ]

        self.assertEqual(
            report["propositions"][conditions["B"]]["status"],
            "T",
        )
        for variable in ("A", "G", "H", "K", "Y"):
            self.assertEqual(
                report["propositions"][conditions[variable]]["status"],
                "U",
            )
        self.assertEqual(path["gate_status"], "U")
        self.assertEqual(
            path["target_impact"]["I"]["status"],
            "U",
        )
        self.assertEqual(
            path["target_impact"]["I"]["interval"],
            [0.0, 1.0],
        )

    def test_single_fact_changes_do_not_complete_the_path(self):
        changes = {
            "H": "deployment.ditto_to_influx.write_prerequisites",
            "K": "capability.ditto_to_influx.vulnerability_effect",
            "Y": "receiver.influxdb.processing_and_controls",
        }

        for variable, proposition_id in changes.items():
            with self.subTest(variable=variable):
                document = deepcopy(self.v3_document)
                item = next(
                    evidence
                    for evidence in document["evidence"]
                    if evidence["proposition_id"] == proposition_id
                )
                item["status"] = "T"
                item["evidence_class"] = "SYNTHETIC_TEST_FIXTURE"
                item["evidence"] = [
                    f"Synthetic test-only evidence for {variable}."
                ]

                report = build_assessment(
                    document,
                    generated_at=FIXED_TIME,
                )
                scenario = next(
                    result
                    for result in report["scenario_results"]
                    if result["scenario_id"] == "RESEARCH-12546-INFLUX"
                )
                path = scenario["paths"][0]
                conditions = path["transitions"][1][
                    "condition_proposition_ids"
                ]

                self.assertEqual(
                    report["propositions"][conditions[variable]][
                        "status"
                    ],
                    "T",
                )
                self.assertEqual(path["gate_status"], "U")
                self.assertNotEqual(
                    scenario["status"],
                    "QUANTIFIED",
                )

    def test_v3_preserves_v2_status_and_bounds_for_all_six(self):
        v2 = {
            item["scenario_id"]: item
            for item in self.v2_report["scenario_results"]
        }
        v3 = {
            item["scenario_id"]: item
            for item in self.v3_report["scenario_results"]
        }

        self.assertEqual(set(v2), set(v3))
        for scenario_id in v2:
            self.assertEqual(
                v2[scenario_id]["status"],
                v3[scenario_id]["status"],
            )
            self.assertEqual(
                v2[scenario_id]["feasibility_envelope"],
                v3[scenario_id]["feasibility_envelope"],
            )
            self.assertEqual(
                v2[scenario_id]["paths"][0]["target_impact"],
                v3[scenario_id]["paths"][0]["target_impact"],
            )

    def test_v3_replay_is_consistent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = save_assessment(
                self.v3_report,
                output_dir=directory,
            )
            replayed = replay_assessment(
                path,
                generated_at=FIXED_TIME,
            )

        self.assertEqual(
            replayed["scenario_results"],
            self.v3_report["scenario_results"],
        )
        self.assertEqual(
            replayed["component_profiles"],
            self.v3_report["component_profiles"],
        )
        self.assertEqual(
            replayed["not_assessed_cves"],
            self.v3_report["not_assessed_cves"],
        )


class ResearchScenarioV4Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.v3_document = load_input(SCENARIO_V3_PATH)
        cls.v3_report = build_assessment(
            cls.v3_document,
            generated_at=FIXED_TIME,
        )
        cls.v4_document = load_input(SCENARIO_V4_PATH)
        cls.v4_report = build_assessment(
            cls.v4_document,
            generated_at=FIXED_TIME,
        )

    def scenario(self, report, scenario_id):
        return next(
            result
            for result in report["scenario_results"]
            if result["scenario_id"] == scenario_id
        )

    def test_v4_observation_records_exact_scope_and_restoration(self):
        observation = self.v4_document["observations"][0]

        self.assertEqual(
            observation["connection_id"],
            "709e3efe-3c62-4e41-9538-dc5316c43efd",
        )
        self.assertEqual(
            observation["source_deployment_id"],
            "mosquitto-vuln-lab",
        )
        self.assertEqual(
            observation["target_deployment_id"],
            "docker",
        )
        self.assertEqual(
            observation["message"]["marker"],
            "LAB-DF-20261115T194201Z-23a7e0e3",
        )
        self.assertEqual(
            observation["observed_results"]["field_before"],
            38.2,
        )
        self.assertEqual(
            observation["observed_results"]["field_after"],
            observation["message"]["marker"],
        )
        self.assertFalse(observation["message"]["retained"])
        temporary = observation["temporary_permissions_and_state"]
        self.assertIn("write iomt/vuln-test", temporary["mqtt_acl"])
        self.assertIn(
            "ditto:inbound-auth-subject",
            temporary["ditto_policy"],
        )
        self.assertEqual(
            temporary["alternate_connection_preserved"],
            "10d920b9-6860-47d8-a66b-1a2039391904",
        )
        self.assertEqual(
            observation["restored_configuration"]["field"],
            38.2,
        )
        self.assertTrue(
            observation["restored_configuration"]["connection"]
        )

    def test_v4_adds_narrow_observations_without_upgrading_broad_claims(self):
        for proposition_id in (
            "observation.mosquitto_to_ditto.normal_dataflow."
            "20261115T194146829204Z",
            "observation.ditto.authorized_processing.normal_message."
            "20261115T194146829204Z",
            "observation.cleanup.mosquitto_to_ditto."
            "20261115T194146829204Z",
        ):
            self.assertEqual(
                self.v4_report["propositions"][proposition_id]["status"],
                "T",
            )

        for proposition_id in (
            "transition.mosquitto_to_ditto.current",
            "capability.2018_12546.transition_to_ditto",
            "receiver.ditto.2018_12546.processing_and_controls",
            "capability.2018_12551.transition_to_ditto",
            "receiver.ditto.2018_12551.processing_and_controls",
        ):
            self.assertEqual(
                self.v4_report["propositions"][proposition_id]["status"],
                "U",
            )

        relationship = next(
            item
            for item in self.v4_document["architecture_evidence"]
            if item["relationship_id"]
            == "relationship.mosquitto-to-ditto"
        )
        self.assertEqual(relationship["status"], "UNKNOWN")

    def test_v4_preserves_all_six_decision_results(self):
        v3 = {
            item["scenario_id"]: item
            for item in self.v3_report["scenario_results"]
        }
        v4 = {
            item["scenario_id"]: item
            for item in self.v4_report["scenario_results"]
        }
        self.assertEqual(set(v3), set(v4))

        for scenario_id in v3:
            self.assertEqual(
                v4[scenario_id]["status"],
                v3[scenario_id]["status"],
            )
            self.assertEqual(
                v4[scenario_id]["feasibility_envelope"],
                v3[scenario_id]["feasibility_envelope"],
            )
            self.assertEqual(
                v4[scenario_id]["paths"][0]["target_impact"],
                v3[scenario_id]["paths"][0]["target_impact"],
            )

    def test_v4_replay_is_consistent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = save_assessment(
                self.v4_report,
                output_dir=directory,
            )
            replayed = replay_assessment(
                path,
                generated_at=FIXED_TIME,
            )

        self.assertEqual(
            replayed["scenario_results"],
            self.v4_report["scenario_results"],
        )
        self.assertEqual(
            replayed["component_profiles"],
            self.v4_report["component_profiles"],
        )
        self.assertEqual(
            replayed["not_assessed_cves"],
            self.v4_report["not_assessed_cves"],
        )
        self.assertEqual(
            replayed["propositions"],
            self.v4_report["propositions"],
        )


class ResearchScenarioV5Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.v4_document = load_input(SCENARIO_V4_PATH)
        cls.v4_report = build_assessment(
            cls.v4_document,
            generated_at=FIXED_TIME,
        )
        cls.v5_document = load_input(SCENARIO_V5_PATH)
        cls.v5_report = build_assessment(
            cls.v5_document,
            generated_at=FIXED_TIME,
        )

    def test_v5_records_both_links_and_csv_readback(self):
        for proposition_id in (
            "observation.mosquitto_to_ditto.mqtt_normal_dataflow."
            "20261116T151603273933Z",
            "observation.ditto_to_influx.normal_event_write."
            "20261116T151603273933Z",
            "observation.end_to_end.normal_telemetry_chain."
            "20261116T151603273933Z",
            "observation.cleanup.end_to_end."
            "20261116T151603273933Z",
        ):
            self.assertEqual(
                self.v5_report["propositions"][proposition_id]["status"],
                "T",
            )

        observation = self.v5_document["observations"][-1]
        self.assertEqual(
            observation["observed_results"]["influx_http_status"],
            204,
        )
        self.assertEqual(
            observation["observed_results"]["readback_status"],
            "CONFIRMED",
        )
        self.assertTrue(
            observation["restored_baseline"][
                "baseline_relationship_remains_unknown"
            ]
        )

    def test_v5_does_not_upgrade_restored_or_cve_specific_claims(self):
        for proposition_id in (
            "transition.mosquitto_to_ditto.current",
            "transition.ditto_to_influx.current",
            "capability.2018_12546.transition_to_ditto",
            "receiver.ditto.2018_12546.processing_and_controls",
            "capability.2018_12551.transition_to_ditto",
            "receiver.ditto.2018_12551.processing_and_controls",
        ):
            self.assertEqual(
                self.v5_report["propositions"][proposition_id]["status"],
                "U",
            )

        for relationship_id in (
            "relationship.mosquitto-to-ditto",
            "relationship.ditto-to-influx",
        ):
            relationship = next(
                item
                for item in self.v5_document["architecture_evidence"]
                if item["relationship_id"] == relationship_id
            )
            self.assertEqual(relationship["status"], "UNKNOWN")

    def test_v5_preserves_all_six_results_and_reproduction_grades(self):
        v4 = {
            item["scenario_id"]: item
            for item in self.v4_report["scenario_results"]
        }
        v5 = {
            item["scenario_id"]: item
            for item in self.v5_report["scenario_results"]
        }
        self.assertEqual(set(v4), set(v5))
        for scenario_id in v4:
            self.assertEqual(v4[scenario_id]["status"], v5[scenario_id]["status"])
            self.assertEqual(
                v4[scenario_id]["feasibility_envelope"],
                v5[scenario_id]["feasibility_envelope"],
            )
            self.assertEqual(
                v4[scenario_id]["paths"][0]["target_impact"],
                v5[scenario_id]["paths"][0]["target_impact"],
            )
            self.assertEqual(
                v4[scenario_id]["paths"][0]["reproduction_grades"],
                v5[scenario_id]["paths"][0]["reproduction_grades"],
            )

    def test_v5_replay_is_consistent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = save_assessment(
                self.v5_report,
                output_dir=directory,
            )
            replayed = replay_assessment(
                path,
                generated_at=FIXED_TIME,
            )

        self.assertEqual(
            replayed["scenario_results"],
            self.v5_report["scenario_results"],
        )
        self.assertEqual(
            replayed["component_profiles"],
            self.v5_report["component_profiles"],
        )
        self.assertEqual(
            replayed["not_assessed_cves"],
            self.v5_report["not_assessed_cves"],
        )
        self.assertEqual(
            replayed["propositions"],
            self.v5_report["propositions"],
        )


class ResearchScenarioV6Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.v5_document = load_input(SCENARIO_V5_PATH)
        cls.v5_report = build_assessment(
            cls.v5_document,
            generated_at=FIXED_TIME,
        )
        cls.v6_document = load_input(SCENARIO_V6_PATH)
        cls.v6_report = build_assessment(
            cls.v6_document,
            generated_at=FIXED_TIME,
        )

    def scenario(self, report, scenario_id):
        return next(
            item
            for item in report["scenario_results"]
            if item["scenario_id"] == scenario_id
        )

    def test_historical_delivery_alone_does_not_establish_controls_or_integrity(self):
        delivery_id = (
            "observation.mosquitto.2018_12546."
            "historical_subscriber_delivery"
        )
        controls_id = "receiver.mosquitto.2018_12546.controls"
        direct = self.scenario(
            self.v6_report,
            "RESEARCH-12546-MOSQUITTO",
        )
        path = direct["paths"][0]

        self.assertEqual(
            self.v6_report["propositions"][delivery_id]["status"],
            "T",
        )
        delivery_source = next(
            item
            for item in self.v6_document["evidence"]
            if item["proposition_id"] == delivery_id
        )
        self.assertEqual(
            delivery_source["reproduction_grade"],
            "MANUALLY_OBSERVED",
        )
        self.assertEqual(
            path["reproduction_grades"]["CVE-2018-12546"],
            "MANUALLY_OBSERVED",
        )
        self.assertEqual(
            path["transitions"][0]["condition_proposition_ids"]["Y"],
            controls_id,
        )
        self.assertEqual(
            self.v6_report["propositions"][controls_id]["status"],
            "U",
        )
        self.assertEqual(
            path["target_impact"]["I"]["status"],
            "U",
        )
        self.assertEqual(
            path["target_impact"]["I"]["interval"],
            [0.0, 1.0],
        )

    def test_direct_transition_and_feasibility_are_corrected(self):
        direct = self.scenario(
            self.v6_report,
            "RESEARCH-12546-MOSQUITTO",
        )
        path = direct["paths"][0]
        self.assertEqual(
            self.v6_report["propositions"][
                "transition.direct_mosquitto_2018_12546.current"
            ]["status"],
            "U",
        )
        self.assertEqual(
            direct["feasibility_envelope"],
            [0.0, 0.7294117647058823],
        )
        self.assertEqual(direct["status"], "PARTIALLY_QUANTIFIED")
        for channel in ("C", "I", "A"):
            self.assertEqual(path["target_impact"][channel]["status"], "U")
            self.assertEqual(
                path["target_impact"][channel]["interval"],
                [0.0, 1.0],
            )

    def test_only_direct_scenario_result_changes(self):
        v5 = {
            item["scenario_id"]: item
            for item in self.v5_report["scenario_results"]
        }
        v6 = {
            item["scenario_id"]: item
            for item in self.v6_report["scenario_results"]
        }
        self.assertEqual(set(v5), set(v6))

        for scenario_id in v5:
            if scenario_id == "RESEARCH-12546-MOSQUITTO":
                self.assertNotEqual(
                    v5[scenario_id]["feasibility_envelope"],
                    v6[scenario_id]["feasibility_envelope"],
                )
                self.assertNotEqual(
                    v5[scenario_id]["paths"][0]["target_impact"],
                    v6[scenario_id]["paths"][0]["target_impact"],
                )
            else:
                self.assertEqual(
                    v5[scenario_id]["status"],
                    v6[scenario_id]["status"],
                )
                self.assertEqual(
                    v5[scenario_id]["feasibility_envelope"],
                    v6[scenario_id]["feasibility_envelope"],
                )
                self.assertEqual(
                    v5[scenario_id]["paths"][0]["target_impact"],
                    v6[scenario_id]["paths"][0]["target_impact"],
                )
            self.assertEqual(
                v5[scenario_id]["paths"][0]["reproduction_grades"],
                v6[scenario_id]["paths"][0]["reproduction_grades"],
            )

    def test_v6_replay_is_consistent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = save_assessment(
                self.v6_report,
                output_dir=directory,
            )
            replayed = replay_assessment(
                path,
                generated_at=FIXED_TIME,
            )

        self.assertEqual(
            replayed["scenario_results"],
            self.v6_report["scenario_results"],
        )
        self.assertEqual(
            replayed["component_profiles"],
            self.v6_report["component_profiles"],
        )
        self.assertEqual(
            replayed["not_assessed_cves"],
            self.v6_report["not_assessed_cves"],
        )
        self.assertEqual(
            replayed["propositions"],
            self.v6_report["propositions"],
        )


class ResearchScenarioV7Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.v6_document = load_input(SCENARIO_V6_PATH)
        cls.v6_report = build_assessment(
            cls.v6_document,
            generated_at=FIXED_TIME,
        )
        cls.v7_document = load_input(SCENARIO_V7_PATH)
        cls.v7_report = build_assessment(
            cls.v7_document,
            generated_at=FIXED_TIME,
        )

    def scenario(self, report, scenario_id):
        return next(
            result
            for result in report["scenario_results"]
            if result["scenario_id"] == scenario_id
        )

    def test_supported_false_acl_condition_produces_zero(self):
        scenario = self.scenario(
            self.v7_report,
            "RESEARCH-12550-MOSQUITTO",
        )
        path = scenario["paths"][0]
        conditions = path["transitions"][0]["condition_proposition_ids"]

        self.assertEqual(
            self.v7_report["propositions"][conditions["A"]]["status"],
            "T",
        )
        self.assertEqual(
            self.v7_report["propositions"][conditions["H"]]["status"],
            "F",
        )
        self.assertEqual(
            self.v7_report["propositions"][conditions["B"]]["status"],
            "T",
        )
        for variable in ("G", "K", "Y"):
            self.assertEqual(
                self.v7_report["propositions"][conditions[variable]][
                    "status"
                ],
                "U",
            )
        self.assertEqual(scenario["status"], "ZERO")
        self.assertEqual(scenario["feasibility_envelope"], [0.0, 0.0])
        self.assertEqual(
            path["reproduction_grades"]["CVE-2018-12550"],
            "NOT_TESTED",
        )
        for channel in ("C", "I", "A"):
            self.assertEqual(path["target_impact"][channel]["status"], "U")
            self.assertEqual(
                path["target_impact"][channel]["interval"],
                [0.0, 1.0],
            )

    def test_insufficient_acl_evidence_remains_unquantified(self):
        document = deepcopy(self.v7_document)
        condition = next(
            item
            for item in document["evidence"]
            if item["proposition_id"]
            == "configuration.2018_12550.empty_or_comment_only_acl"
        )
        condition["status"] = "U"
        condition["evidence_class"] = "EVIDENCE_GAP"
        condition["source"] = "Synthetic test: observation withheld"
        condition["evidence"] = []
        condition["reason"] = "The configuration condition is not established."

        report = build_assessment(document, generated_at=FIXED_TIME)
        scenario = self.scenario(
            report,
            "RESEARCH-12550-MOSQUITTO",
        )
        self.assertEqual(scenario["status"], "UNQUANTIFIED")
        self.assertIsNone(scenario["feasibility_envelope"])

    def test_v7_preserves_all_existing_six_results(self):
        v6 = {
            item["scenario_id"]: item
            for item in self.v6_report["scenario_results"]
        }
        v7 = {
            item["scenario_id"]: item
            for item in self.v7_report["scenario_results"]
        }
        self.assertEqual(set(v6) | {"RESEARCH-12550-MOSQUITTO"}, set(v7))
        for scenario_id in v6:
            self.assertEqual(v6[scenario_id]["status"], v7[scenario_id]["status"])
            self.assertEqual(
                v6[scenario_id]["feasibility_envelope"],
                v7[scenario_id]["feasibility_envelope"],
            )
            self.assertEqual(
                v6[scenario_id]["paths"][0]["target_impact"],
                v7[scenario_id]["paths"][0]["target_impact"],
            )

    def test_v7_replay_is_consistent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = save_assessment(
                self.v7_report,
                output_dir=directory,
            )
            replayed = replay_assessment(
                path,
                generated_at=FIXED_TIME,
            )

        self.assertEqual(
            replayed["scenario_results"],
            self.v7_report["scenario_results"],
        )
        self.assertEqual(
            replayed["component_profiles"],
            self.v7_report["component_profiles"],
        )
        self.assertEqual(
            replayed["not_assessed_cves"],
            self.v7_report["not_assessed_cves"],
        )
        self.assertEqual(
            replayed["propositions"],
            self.v7_report["propositions"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
