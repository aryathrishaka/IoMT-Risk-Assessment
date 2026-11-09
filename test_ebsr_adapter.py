"""Offline integration tests for the deployment-to-EBSR evidence adapter."""

import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import ebsr_adapter
import main
from cve_2018_12546_test import validate_cve_2018_12546


VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"
FIXED_TIME = "2026-11-09T12:00:00+00:00"


def deployment(deployment_id, component_id, display_name, version):
    return {
        "deployment_id": deployment_id,
        "component_id": component_id,
        "display_name": display_name,
        "version": version,
        "discovery_evidence": {
            "image": f"{component_id}:{version}",
            "image_digest": f"sha256:{deployment_id}",
            "version_source": "synthetic_test_fixture",
        },
    }


def assessment_row(cve_id, status="AFFECTED", vector=VECTOR, reason=None):
    return {
        "cve_id": cve_id,
        "status": status,
        "reason": reason or f"{status} synthetic applicability result.",
        "cvss": {
            "scale": "CVSS v3.x",
            "primary": {
                "version": "3.1",
                "score": 6.5,
                "severity": "MEDIUM",
                "vector": vector,
                "source_type": "Primary",
                "source": "synthetic",
            },
            "other": [],
            "all": [],
        },
        "applicability": {
            "status": status,
            "reason": reason or f"{status} synthetic applicability result.",
            "component": {"canonical_id": None},
            "configurations": [],
        },
    }


def assessment_record(
    deployment_id,
    component_id,
    version,
    affected=None,
    unknown=None,
    not_affected=None,
    retrieval_status="COMPLETE",
):
    return {
        "deployment_id": deployment_id,
        "component_id": component_id,
        "component": component_id,
        "version": version,
        "discovery_evidence": {
            "deployment_id": deployment_id,
            "component_id": component_id,
            "version": version,
            "version_source": "synthetic_test_fixture",
        },
        "retrieval": {
            "status": retrieval_status,
            "received": (
                len(affected or [])
                + len(unknown or [])
                + len(not_affected or [])
            ),
            "total_results": (
                len(affected or [])
                + len(unknown or [])
                + len(not_affected or [])
                if retrieval_status == "COMPLETE"
                else None
            ),
            "error": (
                None
                if retrieval_status == "COMPLETE"
                else "Synthetic retrieval interruption."
            ),
        },
        "affected": affected or [],
        "affected_other_scale": [],
        "unknown": unknown or [],
        "not_affected": not_affected or [],
    }


def all_true_conditions():
    return {
        variable: {
            "status": "T",
            "evidence": [f"Synthetic evidence for {variable}."],
        }
        for variable in ebsr_adapter.CONDITION_VARIABLES
        if variable != "B"
    }


def relationship(
    relationship_id,
    source,
    target,
    transition_type,
    status="SUPPORTED",
):
    return {
        "relationship_id": relationship_id,
        "source_deployment_id": source,
        "target_deployment_id": target,
        "transition_type": transition_type,
        "status": status,
        "evidence": (
            [f"Synthetic {transition_type} relationship evidence."]
            if status in ("SUPPORTED", "NOT_SUPPORTED")
            else []
        ),
        "notes": "Synthetic integration evidence; not a live experiment.",
    }


def target_channels(c=False, i=True, a=False, i_magnitude=None):
    values = {}
    for channel, state in (("C", c), ("I", i), ("A", a)):
        values[channel] = {
            "state": "T" if state else "F",
            "evidence": [f"Synthetic target {channel} evidence."],
        }
        if channel == "I" and i_magnitude is not None:
            values[channel]["magnitude"] = i_magnitude
    return values


def scenario_path(
    path_id,
    source,
    target,
    cve_ids,
    transition_type,
    relationship_id,
    conditions=None,
    channels=None,
    reproduction_grades=None,
):
    return {
        "path_id": path_id,
        "source_deployment_id": source,
        "target_deployment_id": target,
        "cve_ids": cve_ids,
        "transition_type": transition_type,
        "relationship_id": relationship_id,
        "transition_description": (
            f"Synthetic {transition_type} transition description."
        ),
        "conditions": (
            all_true_conditions()
            if conditions is None
            else conditions
        ),
        "target_channels": (
            target_channels()
            if channels is None
            else channels
        ),
        "reproduction_grades": reproduction_grades or {},
    }


def base_bundle():
    deployments = [
        deployment(
            "mosq-vuln",
            "mosquitto",
            "Mosquitto Vulnerable Lab",
            "1.5.5",
        ),
        deployment(
            "mosq-control",
            "mosquitto",
            "Mosquitto",
            "2.1.2",
        ),
        deployment(
            "ditto-prod",
            "ditto",
            "Eclipse Ditto",
            "3.9.7",
        ),
        deployment(
            "influx-prod",
            "influxdb",
            "InfluxDB",
            "2.7.11",
        ),
    ]
    relationships = [
        relationship(
            "mq-to-ditto",
            "mosq-vuln",
            "ditto-prod",
            "DF",
            "SUPPORTED",
        ),
        relationship(
            "ditto-to-influx",
            "ditto-prod",
            "influx-prod",
            "LX",
            "CONFLICT",
        ),
        relationship(
            "influx-to-mosq",
            "influx-prod",
            "mosq-control",
            "CT",
            "SUPPORTED",
        ),
    ]
    assessments = [
        assessment_record(
            "mosq-vuln",
            "mosquitto",
            "1.5.5",
            affected=[
                assessment_row("CVE-SYNTH-MQ"),
                assessment_row("CVE-SYNTH-MQ-NO-SCENARIO"),
            ],
        ),
        assessment_record(
            "mosq-control",
            "mosquitto",
            "2.1.2",
            affected=[assessment_row("CVE-SYNTH-MQ-CONTROL")],
            retrieval_status="PARTIAL",
        ),
        assessment_record(
            "ditto-prod",
            "ditto",
            "3.9.7",
            affected=[
                assessment_row("CVE-SYNTH-DITTO"),
                assessment_row("CVE-SYNTH-DITTO-UNKNOWN", status="UNKNOWN"),
            ],
        ),
        assessment_record(
            "influx-prod",
            "influxdb",
            "2.7.11",
            affected=[assessment_row("CVE-SYNTH-INFLUX")],
        ),
    ]
    scenarios = [
        {
            "scenario_id": "SYN-MQ-DF",
            "attacker_id": "ATTACKER-A",
            "target_deployment_id": "ditto-prod",
            "description": "Synthetic DF path with incomplete target impact.",
            "paths": [
                scenario_path(
                    "mq-to-ditto",
                    "mosq-vuln",
                    "ditto-prod",
                    ["CVE-SYNTH-MQ"],
                    "DF",
                    "mq-to-ditto",
                )
            ],
        },
        {
            "scenario_id": "SYN-DITTO-LX",
            "attacker_id": "ATTACKER-B",
            "target_deployment_id": "influx-prod",
            "description": "Synthetic LX path with conflicting architecture evidence.",
            "paths": [
                scenario_path(
                    "ditto-to-influx",
                    "ditto-prod",
                    "influx-prod",
                    ["CVE-SYNTH-DITTO"],
                    "LX",
                    "ditto-to-influx",
                    channels={
                        "C": {"state": "U"},
                        "I": {"state": "U"},
                        "A": {"state": "U"},
                    },
                )
            ],
        },
        {
            "scenario_id": "SYN-INFLUX-CT",
            "attacker_id": "ATTACKER-A",
            "target_deployment_id": "mosq-control",
            "description": "Synthetic CT credential/trust path.",
            "paths": [
                scenario_path(
                    "influx-to-mosq",
                    "influx-prod",
                    "mosq-control",
                    ["CVE-SYNTH-INFLUX"],
                    "CT",
                    "influx-to-mosq",
                    channels=target_channels(
                        c=True,
                        i=False,
                        a=False,
                        i_magnitude=None,
                    ),
                )
            ],
        },
    ]
    return {
        "schema_version": "1.0",
        "assessment_version": "synthetic-integration-1",
        "deployments": deployments,
        "attacker_profiles": [
            {
                "attacker_id": "ATTACKER-A",
                "description": "Synthetic network attacker profile.",
                "capabilities": ["synthetic-network-access"],
            },
            {
                "attacker_id": "ATTACKER-B",
                "description": "Synthetic credential attacker profile.",
                "capabilities": ["synthetic-credential-access"],
            },
        ],
        "architecture_evidence": relationships,
        "cve_assessments": assessments,
        "scenarios": scenarios,
        "validation_records": [
            {
                "deployment_id": "mosq-vuln",
                "cve_id": "CVE-SYNTH-MQ",
                "validation_status": "VALIDATED",
                "manually_recorded": True,
                "independently_reproduced": False,
                "evidence": ["Synthetic manually recorded observation."],
            }
        ],
    }


class AdapterIntegrationTests(unittest.TestCase):

    def test_three_components_and_transition_types_are_evaluated(self):
        report = ebsr_adapter.build_assessment(
            base_bundle(),
            generated_at=FIXED_TIME,
        )

        scenario_ids = {
            result["scenario_id"]
            for result in report["scenario_results"]
        }
        self.assertEqual(
            scenario_ids,
            {"SYN-MQ-DF", "SYN-DITTO-LX", "SYN-INFLUX-CT"},
        )
        transitions = {
            transition
            for result in report["scenario_results"]
            for transition in result["transition_types"]
        }
        self.assertEqual(transitions, {"DF", "LX", "CT"})

    def test_multiple_cves_are_bound_to_one_path(self):
        document = base_bundle()
        document["cve_assessments"][0]["affected"].append(
            assessment_row("CVE-SYNTH-MQ-2")
        )
        document["scenarios"][0]["paths"][0]["cve_ids"].append(
            "CVE-SYNTH-MQ-2"
        )
        report = ebsr_adapter.build_assessment(
            document,
            generated_at=FIXED_TIME,
        )
        scenario = report["scenario_results"][0]
        path = scenario["paths"][0]

        self.assertEqual(
            path["vulnerability_ids"],
            ["CVE-SYNTH-MQ", "CVE-SYNTH-MQ-2"],
        )
        self.assertEqual(len(path["source_impacts"]), 2)
        self.assertEqual(
            path["source_impacts"][0]["source_impact"]["channels"]["I"],
            0.56,
        )

    def test_ordered_chain_keeps_per_step_cves_and_conditions(self):
        document = base_bundle()
        document["architecture_evidence"].append(
            relationship(
                "ditto-to-influx-chain",
                "ditto-prod",
                "influx-prod",
                "LX",
                "SUPPORTED",
            )
        )
        document["scenarios"] = [{
            "scenario_id": "SYN-CHAIN",
            "attacker_id": "ATTACKER-A",
            "target_deployment_id": "influx-prod",
            "paths": [{
                "path_id": "mq-ditto-influx",
                "target_deployment_id": "influx-prod",
                "target_channels": target_channels(
                    i=True,
                    i_magnitude=0.56,
                ),
                "transitions": [
                    {
                        "step_id": "mq-to-ditto",
                        "source_deployment_id": "mosq-vuln",
                        "target_deployment_id": "ditto-prod",
                        "transition_type": "DF",
                        "relationship_id": "mq-to-ditto",
                        "cve_ids": ["CVE-SYNTH-MQ"],
                        "conditions": all_true_conditions(),
                    },
                    {
                        "step_id": "ditto-to-influx",
                        "source_deployment_id": "ditto-prod",
                        "target_deployment_id": "influx-prod",
                        "transition_type": "LX",
                        "relationship_id": "ditto-to-influx-chain",
                        "cve_ids": ["CVE-SYNTH-DITTO"],
                        "conditions": all_true_conditions(),
                    },
                ],
            }],
        }]

        report = ebsr_adapter.build_assessment(
            document,
            generated_at=FIXED_TIME,
        )
        path = report["scenario_results"][0]["paths"][0]

        self.assertEqual(
            [item["step_id"] for item in path["transitions"]],
            ["mq-to-ditto", "ditto-to-influx"],
        )
        self.assertEqual(
            [item["source_deployment_id"] for item in path["transitions"]],
            ["mosq-vuln", "ditto-prod"],
        )
        self.assertEqual(
            path["cve_deployment_ids"],
            {
                "CVE-SYNTH-MQ": "mosq-vuln",
                "CVE-SYNTH-DITTO": "ditto-prod",
            },
        )
        self.assertEqual(
            [
                step["deployment_id"]
                for step in path["vulnerability_steps"]
            ],
            ["mosq-vuln", "ditto-prod"],
        )
        self.assertEqual(
            path["transition_types"],
            ["DF", "LX"],
        )
        first_conditions = set(
            path["transitions"][0][
                "condition_proposition_ids"
            ].values()
        )
        second_conditions = set(
            path["transitions"][1][
                "condition_proposition_ids"
            ].values()
        )
        self.assertEqual(
            set(path["transitions"][0][
                "condition_proposition_ids"
            ]),
            set(ebsr_adapter.CONDITION_VARIABLES),
        )
        self.assertTrue(
            first_conditions.isdisjoint(second_conditions)
        )
        self.assertEqual(path["gate_status"], "T")

    def test_non_ordered_transition_chain_is_rejected(self):
        document = base_bundle()
        document["scenarios"] = [{
            "scenario_id": "SYN-BROKEN-CHAIN",
            "attacker_id": "ATTACKER-A",
            "target_deployment_id": "influx-prod",
            "paths": [{
                "path_id": "broken-chain",
                "target_channels": target_channels(),
                "transitions": [
                    {
                        "step_id": "one",
                        "source_deployment_id": "mosq-vuln",
                        "target_deployment_id": "ditto-prod",
                        "transition_type": "DF",
                        "relationship_id": "mq-to-ditto",
                        "cve_ids": ["CVE-SYNTH-MQ"],
                        "conditions": all_true_conditions(),
                    },
                    {
                        "step_id": "two",
                        "source_deployment_id": "mosq-control",
                        "target_deployment_id": "influx-prod",
                        "transition_type": "DF",
                        "relationship_id": "influx-to-mosq",
                        "cve_ids": [],
                        "conditions": all_true_conditions(),
                    },
                ],
            }],
        }]

        report = ebsr_adapter.build_assessment(
            document,
            generated_at=FIXED_TIME,
        )

        self.assertEqual(report["scenario_results"], [])
        self.assertTrue(any(
            "not an ordered deployment chain" in error["reason"]
            for error in report["scenario_errors"]
        ))

    def test_shared_evidence_conflict_applies_to_every_dependent_path(self):
        document = base_bundle()
        document["evidence"] = [
            {
                "proposition_id": "shared.controller.verified",
                "status": "T",
                "source": "synthetic-source-a",
                "evidence": ["Synthetic supporting observation."],
            },
            {
                "proposition_id": "shared.controller.verified",
                "status": "F",
                "source": "synthetic-source-b",
                "evidence": ["Synthetic opposing observation."],
            },
        ]
        base_path = document["scenarios"][0]["paths"][0]
        first = all_true_conditions()
        second = all_true_conditions()
        first["G"] = {"proposition_id": "shared.controller.verified"}
        second["G"] = {"proposition_id": "shared.controller.verified"}
        document["scenarios"] = [{
            "scenario_id": "SYN-SHARED",
            "attacker_id": "ATTACKER-A",
            "target_deployment_id": "ditto-prod",
            "paths": [
                {
                    **base_path,
                    "path_id": "shared-a",
                    "conditions": first,
                },
                {
                    **base_path,
                    "path_id": "shared-b",
                    "conditions": second,
                },
            ],
        }]

        report = ebsr_adapter.build_assessment(
            document,
            generated_at=FIXED_TIME,
        )
        scenario = report["scenario_results"][0]

        self.assertEqual(
            report["propositions"]["shared.controller.verified"]["status"],
            "X",
        )
        self.assertEqual(
            [path["gate_status"] for path in scenario["paths"]],
            ["X", "X"],
        )

    def test_same_proposition_asserted_differently_resolves_as_conflict(self):
        document = base_bundle()
        base_path = document["scenarios"][0]["paths"][0]
        first = all_true_conditions()
        second = all_true_conditions()
        first["G"] = {
            "proposition_id": "shared.capability",
            "status": "T",
            "evidence": ["Synthetic path A supports the fact."],
        }
        second["G"] = {
            "proposition_id": "shared.capability",
            "status": "F",
            "evidence": ["Synthetic path B contradicts the fact."],
        }
        document["scenarios"] = [{
            "scenario_id": "SYN-INLINE-SHARED",
            "attacker_id": "ATTACKER-A",
            "target_deployment_id": "ditto-prod",
            "paths": [
                {**base_path, "path_id": "inline-a", "conditions": first},
                {**base_path, "path_id": "inline-b", "conditions": second},
            ],
        }]

        report = ebsr_adapter.build_assessment(
            document,
            generated_at=FIXED_TIME,
        )

        self.assertEqual(
            report["propositions"]["shared.capability"]["status"],
            "X",
        )
        self.assertEqual(
            [
                path["gate_status"]
                for path in report["scenario_results"][0]["paths"]
            ],
            ["X", "X"],
        )

    def test_duplicate_path_id_is_reported_and_not_evaluated_twice(self):
        document = base_bundle()
        path = document["scenarios"][0]["paths"][0]
        duplicate = json.loads(json.dumps(path))
        duplicate["target_channels"]["I"]["magnitude"] = 0.99
        document["scenarios"][0]["paths"] = [
            path,
            duplicate,
        ]

        report = ebsr_adapter.build_assessment(
            document,
            generated_at=FIXED_TIME,
        )

        self.assertEqual(
            len(report["scenario_results"][0]["paths"]),
            1,
        )
        self.assertIsNone(
            report["scenario_results"][0]["paths"][0][
                "target_impact"
            ]["I"]["interval"]
        )
        self.assertTrue(any(
            error.get("kind") is None
            and "Duplicate path_id" in error["reason"]
            for error in report["scenario_errors"]
        ))

    def test_ambiguous_deployment_identifier_is_not_silently_overwritten(self):
        document = base_bundle()
        document["deployments"].append(
            deployment(
                "mosq-vuln",
                "mosquitto",
                "Conflicting Mosquitto deployment",
                "9.9.9",
            )
        )

        report = ebsr_adapter.build_assessment(
            document,
            generated_at=FIXED_TIME,
        )

        self.assertTrue(any(
            error["kind"] == "DUPLICATE_IDENTIFIER"
            and error["identifier"] == "mosq-vuln"
            for error in report["input_errors"]
        ))
        self.assertFalse(any(
            "mosq-vuln"
            in path["cve_deployment_ids"].values()
            for scenario in report["scenario_results"]
            for path in scenario["paths"]
        ))

    def test_contradictory_relationship_records_are_reconciled(self):
        document = base_bundle()
        document["architecture_evidence"].append(
            relationship(
                "mq-to-ditto",
                "mosq-vuln",
                "ditto-prod",
                "DF",
                "NOT_SUPPORTED",
            )
        )

        report = ebsr_adapter.build_assessment(
            document,
            generated_at=FIXED_TIME,
        )
        scenario = report["scenario_results"][0]
        path = scenario["paths"][0]
        b_id = path["transitions"][0][
            "condition_proposition_ids"
        ]["B"]

        self.assertEqual(report["propositions"][b_id]["status"], "X")
        self.assertEqual(path["gate_status"], "X")
        self.assertEqual(
            len(path["transitions"][0]["relationship_records"]),
            2,
        )

    def test_relationship_without_transition_type_cannot_establish_b(self):
        document = base_bundle()
        document["architecture_evidence"][0].pop(
            "transition_type"
        )
        document["architecture_evidence"][0][
            "relationship_type"
        ] = "data_flow"

        report = ebsr_adapter.build_assessment(
            document,
            generated_at=FIXED_TIME,
        )
        path = report["scenario_results"][0]["paths"][0]
        b_id = path["transitions"][0][
            "condition_proposition_ids"
        ]["B"]
        b_record = report["propositions"][b_id]

        self.assertEqual(b_record["status"], "U")
        self.assertIn(
            "no explicit DF/LX/CT",
            " ".join(
                source.get("reason") or ""
                for source in b_record["sources"]
            ),
        )
        self.assertNotEqual(path["gate_status"], "T")

    def test_relationship_type_mismatch_is_conflict(self):
        document = base_bundle()
        document["architecture_evidence"][0][
            "transition_type"
        ] = "CT"

        report = ebsr_adapter.build_assessment(
            document,
            generated_at=FIXED_TIME,
        )
        path = report["scenario_results"][0]["paths"][0]
        b_id = path["transitions"][0][
            "condition_proposition_ids"
        ]["B"]

        self.assertEqual(report["propositions"][b_id]["status"], "X")
        self.assertEqual(path["gate_status"], "X")

    def test_direct_source_impact_profile_is_supported(self):
        document = base_bundle()
        conditions = all_true_conditions()
        conditions["B"] = {
            "status": "T",
            "evidence": ["Synthetic direct-effect condition."],
        }
        channels = target_channels(i=True, i_magnitude=0.56)
        document["scenarios"] = [{
            "scenario_id": "SYN-DIRECT",
            "attacker_id": "ATTACKER-A",
            "target_deployment_id": "mosq-vuln",
            "paths": [
                scenario_path(
                    "direct-integrity",
                    "mosq-vuln",
                    "mosq-vuln",
                    ["CVE-SYNTH-MQ"],
                    "DIRECT",
                    None,
                    conditions=conditions,
                    channels=channels,
                )
            ],
        }]
        report = ebsr_adapter.build_assessment(
            document,
            generated_at=FIXED_TIME,
        )
        path = report["scenario_results"][0]["paths"][0]

        self.assertEqual(path["transition_type"], "DIRECT")
        self.assertEqual(
            path["target_impact"]["I"]["interval"],
            [0.56, 0.56],
        )
        self.assertEqual(
            path["source_impacts"][0]["source_impact"]["channels"]["I"],
            0.56,
        )

    def test_target_impact_is_not_copied_from_source_cvss_impact(self):
        report = ebsr_adapter.build_assessment(
            base_bundle(),
            generated_at=FIXED_TIME,
        )
        scenario = next(
            result
            for result in report["scenario_results"]
            if result["scenario_id"] == "SYN-MQ-DF"
        )
        path = scenario["paths"][0]
        source_impact = path["source_impacts"][0]["source_impact"]

        self.assertAlmostEqual(
            source_impact["channels"]["I"],
            0.56,
        )
        self.assertEqual(
            path["target_impact"]["C"]["interval"],
            [0.0, 0.0],
        )
        self.assertEqual(
            path["target_impact"]["I"]["status"],
            "UNQUANTIFIED",
        )
        self.assertIsNone(
            path["target_impact"]["I"]["interval"],
        )
        self.assertEqual(
            path["target_impact"]["A"]["interval"],
            [0.0, 0.0],
        )

    def test_feasibility_is_quantified_when_target_impact_is_incomplete(self):
        report = ebsr_adapter.build_assessment(
            base_bundle(),
            generated_at=FIXED_TIME,
        )
        scenario = next(
            result
            for result in report["scenario_results"]
            if result["scenario_id"] == "SYN-MQ-DF"
        )

        self.assertEqual(scenario["status"], "PARTIALLY_QUANTIFIED")
        self.assertAlmostEqual(
            scenario["feasibility_envelope"][0],
            0.729411765,
            places=8,
        )
        self.assertEqual(
            scenario["unquantified_target_impact_paths"][0]["channels"],
            ["I"],
        )

    def test_conflicting_architecture_evidence_remains_conflict(self):
        report = ebsr_adapter.build_assessment(
            base_bundle(),
            generated_at=FIXED_TIME,
        )
        scenario = next(
            result
            for result in report["scenario_results"]
            if result["scenario_id"] == "SYN-DITTO-LX"
        )
        path = scenario["paths"][0]

        self.assertEqual(scenario["status"], "X")
        self.assertEqual(path["gate_status"], "X")
        self.assertEqual(path["feasibility"]["status"], "X")
        self.assertIsNone(path["feasibility"]["interval"])

    def test_attacker_profiles_are_independent(self):
        report = ebsr_adapter.build_assessment(
            base_bundle(),
            generated_at=FIXED_TIME,
        )
        by_component = report["system_profile"]["components"]

        self.assertIn(
            "ATTACKER-A",
            by_component["ditto-prod"],
        )
        self.assertIn(
            "ATTACKER-B",
            by_component["influx-prod"],
        )
        self.assertNotIn(
            "ATTACKER-B",
            by_component["ditto-prod"],
        )

    def test_separate_mosquitto_deployments_remain_separate(self):
        report = ebsr_adapter.build_assessment(
            base_bundle(),
            generated_at=FIXED_TIME,
        )
        not_assessed = {
            (record["deployment_id"], record["cve_id"])
            for record in report["not_assessed_cves"]
        }

        self.assertIn(
            ("mosq-vuln", "CVE-SYNTH-MQ-NO-SCENARIO"),
            not_assessed,
        )
        self.assertIn(
            ("mosq-control", "CVE-SYNTH-MQ-CONTROL"),
            not_assessed,
        )
        self.assertNotIn(
            ("mosq-vuln", "CVE-SYNTH-MQ"),
            not_assessed,
        )
        self.assertIn(
            ("ditto-prod", "CVE-SYNTH-DITTO-UNKNOWN"),
            not_assessed,
        )

    def test_uncovered_affected_cve_is_not_assessed_not_zero(self):
        report = ebsr_adapter.build_assessment(
            base_bundle(),
            generated_at=FIXED_TIME,
        )
        record = next(
            item
            for item in report["not_assessed_cves"]
            if item["cve_id"] == "CVE-SYNTH-MQ-NO-SCENARIO"
        )

        self.assertEqual(record["status"], "NOT_ASSESSED")
        self.assertEqual(record["applicability_status"], "AFFECTED")
        self.assertIn("No matching scenario", record["reason"])
        self.assertNotEqual(record["status"], "ZERO")

    def test_failed_retrieval_does_not_imply_absence(self):
        document = base_bundle()
        failed = assessment_record(
            "ditto-broken",
            "ditto",
            "3.9.7",
            retrieval_status="FAILED",
        )
        document["deployments"].append(
            deployment(
                "ditto-broken",
                "ditto",
                "Eclipse Ditto",
                "3.9.7",
            )
        )
        document["cve_assessments"].append(failed)
        report = ebsr_adapter.build_assessment(
            document,
            generated_at=FIXED_TIME,
        )
        gap = next(
            gap
            for gap in report["evidence_gaps"]
            if gap.get("deployment_id") == "ditto-broken"
        )

        self.assertEqual(gap["status"], "FAILED")
        self.assertIn("interruption", gap["detail"])
        self.assertFalse(any(
            profile["deployment_id"] == "ditto-broken"
            for profile in report["component_profiles"]
        ))

    def test_complete_empty_retrieval_is_not_reported_as_failure(self):
        document = base_bundle()
        document["cve_assessments"] = [
            assessment_record(
                "ditto-empty",
                "ditto",
                "3.9.7",
                retrieval_status="COMPLETE",
            )
        ]
        document["deployments"].append(
            deployment(
                "ditto-empty",
                "ditto",
                "Eclipse Ditto",
                "3.9.7",
            )
        )
        document["scenarios"] = []
        report = ebsr_adapter.build_assessment(
            document,
            generated_at=FIXED_TIME,
        )

        self.assertEqual(report["not_assessed_cves"], [])
        self.assertFalse(any(
            gap.get("deployment_id") == "ditto-empty"
            for gap in report["evidence_gaps"]
        ))
        self.assertEqual(report["scenario_results"], [])

    def test_omitted_mandatory_condition_remains_unknown(self):
        document = base_bundle()
        conditions = all_true_conditions()
        conditions.pop("Y")
        document["scenarios"] = [{
            "scenario_id": "SYN-OMITTED",
            "attacker_id": "ATTACKER-A",
            "target_deployment_id": "ditto-prod",
            "paths": [
                scenario_path(
                    "omitted-Y",
                    "mosq-vuln",
                    "ditto-prod",
                    ["CVE-SYNTH-MQ"],
                    "DF",
                    "mq-to-ditto",
                    conditions=conditions,
                )
            ],
        }]
        report = ebsr_adapter.build_assessment(
            document,
            generated_at=FIXED_TIME,
        )
        path = report["scenario_results"][0]["paths"][0]
        y_id = path["transitions"][0][
            "condition_proposition_ids"
        ]["Y"]

        self.assertEqual(report["propositions"][y_id]["status"], "U")
        self.assertIn("omitted", report["propositions"][y_id]["reason"])
        self.assertNotEqual(path["gate_status"], "T")
        self.assertEqual(path["feasibility"]["status"], "UNCERTAIN")

    def test_missing_relationship_evidence_keeps_b_unknown(self):
        document = base_bundle()
        document["architecture_evidence"] = []
        report = ebsr_adapter.build_assessment(
            document,
            generated_at=FIXED_TIME,
        )
        scenario = next(
            result
            for result in report["scenario_results"]
            if result["scenario_id"] == "SYN-MQ-DF"
        )
        b_id = scenario["paths"][0]["transitions"][0][
            "condition_proposition_ids"
        ]["B"]

        self.assertEqual(report["propositions"][b_id]["status"], "U")
        self.assertEqual(scenario["status"], "PARTIALLY_QUANTIFIED")
        self.assertEqual(
            scenario["paths"][0]["gate_status"],
            "U",
        )
        self.assertIsNotNone(scenario["feasibility_envelope"])

    def test_invalid_cvss_vector_remains_unquantified(self):
        document = base_bundle()
        document["cve_assessments"][0]["affected"][0] = assessment_row(
            "CVE-SYNTH-MQ",
            vector=VECTOR.replace("S:U", "S:INVALID"),
        )
        report = ebsr_adapter.build_assessment(
            document,
            generated_at=FIXED_TIME,
        )
        path = next(
            result["paths"][0]
            for result in report["scenario_results"]
            if result["scenario_id"] == "SYN-MQ-DF"
        )

        self.assertEqual(path["feasibility"]["status"], "UNQUANTIFIED")
        self.assertIsNone(path["feasibility"]["interval"])
        self.assertIsNone(
            path["source_impacts"][0]["source_impact"]
        )

    def test_manual_validation_is_not_upgraded(self):
        report = ebsr_adapter.build_assessment(
            base_bundle(),
            generated_at=FIXED_TIME,
        )
        scenario = next(
            result
            for result in report["scenario_results"]
            if result["scenario_id"] == "SYN-MQ-DF"
        )

        self.assertEqual(
            scenario["paths"][0]["reproduction_grades"],
            {"CVE-SYNTH-MQ": "MANUALLY_OBSERVED"},
        )

    def test_existing_cve_validation_record_remains_manual(self):
        document = base_bundle()
        validation = validate_cve_2018_12546()
        validation["deployment_id"] = "mosq-vuln"
        document["validation_records"] = [validation]
        document["cve_assessments"][0]["affected"][0][
            "cve_id"
        ] = "CVE-2018-12546"
        document["scenarios"][0]["paths"][0]["cve_ids"] = [
            "CVE-2018-12546"
        ]

        report = ebsr_adapter.build_assessment(
            document,
            generated_at=FIXED_TIME,
        )
        scenario = report["scenario_results"][0]
        reproduction = scenario["paths"][0][
            "reproduction_evidence"
        ]["mosq-vuln::CVE-2018-12546"]

        self.assertEqual(
            reproduction["grade"],
            "MANUALLY_OBSERVED",
        )
        self.assertEqual(
            reproduction["validation_record"]["validation_status"],
            "VALIDATED",
        )
        self.assertFalse(
            reproduction["validation_record"].get(
                "independently_reproduced",
                False,
            )
        )

    def test_target_conflict_does_not_erase_feasibility(self):
        document = base_bundle()
        channels = target_channels()
        channels["I"] = {
            "state": "X",
            "evidence": ["Synthetic conflicting target consequence."],
        }
        document["scenarios"][0]["paths"][0]["target_channels"] = channels
        report = ebsr_adapter.build_assessment(
            document,
            generated_at=FIXED_TIME,
        )
        scenario = report["scenario_results"][0]

        self.assertEqual(scenario["status"], "PARTIALLY_QUANTIFIED")
        self.assertEqual(
            scenario["conflict_target_impact_paths"][0]["channels"],
            ["I"],
        )
        self.assertIsNotNone(scenario["feasibility_envelope"])

    def test_report_is_json_serialisable(self):
        report = ebsr_adapter.build_assessment(
            base_bundle(),
            generated_at=FIXED_TIME,
        )
        encoded = json.dumps(report)
        decoded = json.loads(encoded)

        self.assertEqual(
            decoded["schema_version"],
            ebsr_adapter.SCHEMA_VERSION,
        )
        self.assertIn("adapter_input", decoded)
        self.assertIn("scenario_results", decoded)
        self.assertIn("target_profiles", decoded)
        self.assertIn("decision_trace", decoded)
        self.assertIn("not_assessed_cves", decoded)

    def test_offline_replay_reproduces_scenario_results(self):
        report = ebsr_adapter.build_assessment(
            base_bundle(),
            generated_at=FIXED_TIME,
        )

        with tempfile.TemporaryDirectory() as directory:
            path = ebsr_adapter.save_assessment(
                report,
                output_dir=directory,
            )
            replay = ebsr_adapter.replay_assessment(
                path,
                generated_at=FIXED_TIME,
            )

            self.assertIn("v synthetic" .replace(" ", ""), Path(path).name)
            self.assertEqual(
                replay["scenario_results"],
                report["scenario_results"],
            )
            self.assertEqual(
                replay["component_profiles"],
                report["component_profiles"],
            )
            self.assertEqual(
                replay["not_assessed_cves"],
                report["not_assessed_cves"],
            )
            self.assertEqual(
                replay["replay"]["source_generated_at"],
                FIXED_TIME,
            )

    def test_save_does_not_overwrite_existing_report(self):
        report = ebsr_adapter.build_assessment(
            base_bundle(),
            generated_at=FIXED_TIME,
        )

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "assessment.json"
            first = Path(
                ebsr_adapter.save_assessment(
                    report,
                    output_path=target,
                )
            )
            second = Path(
                ebsr_adapter.save_assessment(
                    report,
                    output_path=target,
                )
            )

            self.assertTrue(first.exists())
            self.assertTrue(second.exists())
            self.assertNotEqual(first, second)


class MainWorkflowTests(unittest.TestCase):

    def cve_item(self):
        return {
            "cve": {
                "id": "CVE-SYNTH-MQ",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Synthetic integration CVE.",
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [{
                        "type": "Primary",
                        "source": "synthetic",
                        "cvssData": {
                            "version": "3.1",
                            "baseScore": 6.5,
                            "baseSeverity": "MEDIUM",
                            "vectorString": VECTOR,
                        },
                    }]
                },
                "configurations": [],
            }
        }

    def test_main_saves_ebsr_report_and_offline_evidence(self):
        item = self.cve_item()
        selected = {
            "Mosquitto [mosq-vuln]": {
                "software": "mosquitto",
                "applicability_component": "mosquitto",
                "architecture_component": "Mosquitto",
                "component_id": "mosquitto",
                "deployment_id": "mosq-vuln",
                "version": "1.5.5",
                "container": "mosquitto-vuln-lab",
                "image": "efrecon/mosquitto:1.5.5",
                "status": "Detected",
                "diagnostic": False,
                "discovery_evidence": {
                    "deployment_id": "mosq-vuln",
                    "image_digest": "sha256:synthetic",
                },
            }
        }
        retrieval = {
            "status": "COMPLETE",
            "items": [item],
            "received": 1,
            "total_results": 1,
            "error": None,
            "assessments": {
                "affected": [assessment_row("CVE-SYNTH-MQ")],
                "unknown": [],
                "not_affected": [],
            },
        }
        bundle = base_bundle()

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(
                main,
                "get_available_software",
                return_value=selected,
            ):
                with patch.object(
                    main,
                    "get_vulnerabilities",
                    return_value=([item], [], retrieval),
                ):
                    with patch.object(
                        main,
                        "assess_cvss",
                        return_value=None,
                    ):
                        with patch.object(
                            main,
                            "get_attack_path",
                            return_value=["Mosquitto", "Eclipse Ditto"],
                        ):
                            with patch(
                                "builtins.input",
                                side_effect=["1", "1"],
                            ):
                                with redirect_stdout(io.StringIO()):
                                    main.main(
                                        ebsr_input=bundle,
                                        ebsr_output_path=directory,
                                    )

            reports = list(Path(directory).glob("*.json"))
            self.assertEqual(len(reports), 1)
            report = json.loads(reports[0].read_text(encoding="utf-8"))

        self.assertEqual(
            report["scenario_results"][0]["scenario_id"],
            "SYN-MQ-DF",
        )
        self.assertEqual(
            next(
                assessment
                for assessment in report["input_evidence"][
                    "cve_assessments"
                ]
                if assessment["deployment_id"] == "mosq-vuln"
            )["retrieval"]["status"],
            "COMPLETE",
        )
        self.assertEqual(
            next(
                deployment
                for deployment in report["input_evidence"][
                    "deployments"
                ]
                if deployment["deployment_id"] == "mosq-vuln"
            )["deployment_id"],
            "mosq-vuln",
        )
        self.assertTrue(report["adapter_input"])

    def test_main_without_scenarios_reports_not_assessed(self):
        item = self.cve_item()
        selected = {
            "Mosquitto": {
                "software": "mosquitto",
                "version": "1.5.5",
                "container": "mosquitto-vuln-lab",
                "image": "efrecon/mosquitto:1.5.5",
                "deployment_id": "mosq-vuln",
                "component_id": "mosquitto",
                "status": "Detected",
            }
        }
        retrieval = {
            "status": "COMPLETE",
            "items": [item],
            "received": 1,
            "total_results": 1,
            "error": None,
            "assessments": {
                "affected": [assessment_row("CVE-SYNTH-MQ")],
                "unknown": [],
                "not_affected": [],
            },
        }
        output = io.StringIO()

        with patch.object(
            main,
            "get_available_software",
            return_value=selected,
        ):
            with patch.object(
                main,
                "get_vulnerabilities",
                return_value=([item], [], retrieval),
            ):
                with patch.object(
                    main,
                    "assess_cvss",
                    return_value=None,
                ):
                    with patch.object(
                        main,
                        "get_attack_path",
                        return_value=["Mosquitto"],
                    ):
                        with patch(
                            "builtins.input",
                            side_effect=["1", "1"],
                        ):
                            with redirect_stdout(output):
                                report = main.main()

        self.assertEqual(report, None)
        printed = output.getvalue()
        self.assertIn("Scenario result: NOT_ASSESSED", printed)
        self.assertIn("CVE-SYNTH-MQ", printed)

    def test_main_persists_failed_empty_and_unassessed_outcomes(self):
        item = self.cve_item()
        selected = {
            "Mosquitto [mosq-vuln]": {
                "software": "mosquitto",
                "applicability_component": "mosquitto",
                "architecture_component": "Mosquitto",
                "component_id": "mosquitto",
                "deployment_id": "mosq-vuln",
                "version": "1.5.5",
                "container": "mosquitto-vuln-lab",
                "image": "efrecon/mosquitto:1.5.5",
                "status": "Detected",
                "diagnostic": False,
                "discovery_evidence": {
                    "deployment_id": "mosq-vuln",
                },
            }
        }
        cases = [
            {
                "name": "failed",
                "status": "FAILED",
                "items": [],
                "received": 0,
                "total": None,
                "error": "Synthetic transport failure.",
                "assessments": {
                    "affected": [],
                    "unknown": [],
                    "not_affected": [],
                },
                "unknown": [],
            },
            {
                "name": "complete-empty",
                "status": "COMPLETE",
                "items": [],
                "received": 0,
                "total": 0,
                "error": None,
                "assessments": {
                    "affected": [],
                    "unknown": [],
                    "not_affected": [],
                },
                "unknown": [],
            },
            {
                "name": "unknown-only",
                "status": "COMPLETE",
                "items": [item],
                "received": 1,
                "total": 1,
                "error": None,
                "assessments": {
                    "affected": [],
                    "unknown": [
                        assessment_row(
                            "CVE-SYNTH-MQ",
                            status="UNKNOWN",
                        )
                    ],
                    "not_affected": [],
                },
                "unknown": [{
                    "item": item,
                    "status": "UNKNOWN",
                    "reason": "Synthetic unknown applicability.",
                }],
            },
        ]

        for case in cases:
            with self.subTest(case=case["name"]):
                retrieval = {
                    "status": case["status"],
                    "items": case["items"],
                    "received": case["received"],
                    "total_results": case["total"],
                    "error": case["error"],
                    "assessments": case["assessments"],
                }

                with tempfile.TemporaryDirectory() as directory:
                    with patch.object(
                        main,
                        "get_available_software",
                        return_value=selected,
                    ):
                        with patch.object(
                            main,
                            "get_vulnerabilities",
                            return_value=(
                                [],
                                case["unknown"],
                                retrieval,
                            ),
                        ):
                            with patch.object(
                                main,
                                "get_attack_path",
                                side_effect=AssertionError(
                                    "No affected CVE should reach an attack path"
                                ),
                            ):
                                with patch(
                                    "builtins.input",
                                    return_value="1",
                                ):
                                    with redirect_stdout(io.StringIO()):
                                        main.main(
                                            ebsr_output_path=directory
                                        )

                    reports = list(Path(directory).glob("*.json"))
                    self.assertEqual(len(reports), 1)
                    report = json.loads(
                        reports[0].read_text(encoding="utf-8")
                    )

                assessment = next(
                    item
                    for item in report["input_evidence"][
                        "cve_assessments"
                    ]
                    if item["deployment_id"] == "mosq-vuln"
                )
                self.assertEqual(
                    assessment["retrieval"]["status"],
                    case["status"],
                )
                if case["name"] == "failed":
                    self.assertEqual(
                        report["evidence_gaps"][0]["status"],
                        "FAILED",
                    )
                elif case["name"] == "complete-empty":
                    self.assertEqual(report["not_assessed_cves"], [])
                    self.assertEqual(report["scenario_results"], [])
                else:
                    self.assertEqual(
                        report["not_assessed_cves"][0]["cve_id"],
                        "CVE-SYNTH-MQ",
                    )

    def test_cli_replay_never_calls_discovery_or_nvd(self):
        report = ebsr_adapter.build_assessment(
            base_bundle(),
            generated_at=FIXED_TIME,
        )

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.json"
            destination = Path(directory) / "replay.json"
            ebsr_adapter.save_assessment(
                report,
                output_path=source,
            )

            with patch.object(
                main,
                "get_available_software",
                side_effect=AssertionError("Docker discovery was called"),
            ):
                with patch.object(
                    main,
                    "get_vulnerabilities",
                    side_effect=AssertionError("NVD retrieval was called"),
                ):
                    with redirect_stdout(io.StringIO()):
                        main.run_cli([
                            "--ebsr-replay",
                            str(source),
                            "--ebsr-out",
                            str(destination),
                        ])

            replay = json.loads(
                destination.read_text(encoding="utf-8")
            )

        self.assertEqual(
            replay["replay"]["source_generated_at"],
            FIXED_TIME,
        )
        self.assertEqual(
            replay["scenario_results"],
            report["scenario_results"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
