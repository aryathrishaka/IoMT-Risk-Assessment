"""Focused unit tests for the pure EBSR evaluator."""

import json
import unittest

import ebsr


VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"


def path(
    path_id,
    conditions=None,
    vulnerabilities=None,
    actions=None,
    channels=None
):
    return {
        "path_id": path_id,
        "condition_ids": conditions or [],
        "vulnerability_steps": vulnerabilities or [],
        "action_steps": actions or [],
        "target_channels": channels or {}
    }


def vulnerability(
    cve_id="CVE-1",
    vector=VECTOR,
    conditions=None
):
    return {
        "cve_id": cve_id,
        "component": "Mosquitto",
        "cvss_vector": vector,
        "condition_ids": conditions or [],
        "reproduction_grade": "NOT_TESTED"
    }


def channel(proposition_id, magnitude=None):
    result = {
        "proposition_id": proposition_id
    }

    if magnitude is not None:
        result["magnitude"] = magnitude

    return result


class EvidenceTests(unittest.TestCase):

    def test_mandatory_evidence_precedence(self):
        self.assertEqual(
            ebsr.combine_evidence(["T", "F", "X"]),
            "F"
        )
        self.assertEqual(
            ebsr.combine_evidence(["T", "X"]),
            "X"
        )
        self.assertEqual(
            ebsr.combine_evidence(["T", "U"]),
            "U"
        )

    def test_alternative_evidence_precedence(self):
        self.assertEqual(
            ebsr.combine_evidence(["F", "T", "X"], "OR"),
            "T"
        )
        self.assertEqual(
            ebsr.combine_evidence(["F", "X"], "OR"),
            "X"
        )
        self.assertEqual(
            ebsr.combine_evidence(["F", "U"], "OR"),
            "U"
        )

    def test_missing_proposition_is_unknown(self):
        self.assertEqual(
            ebsr.evaluate_propositions(["missing"], {}),
            "U"
        )

    def test_conflict_is_local(self):
        propositions = {
            "unrelated": "X",
            "supported": "T"
        }

        self.assertEqual(
            ebsr.evaluate_propositions(
                ["supported"],
                propositions
            ),
            "T"
        )


class CvssTests(unittest.TestCase):

    def test_v31_exploitability_is_normalized(self):
        value = ebsr.normalise_cvss_v31_exploitability(VECTOR)

        self.assertAlmostEqual(value, 0.729411765, places=8)

    def test_non_v31_vector_is_not_quantified(self):
        vector = VECTOR.replace("3.1", "3.0")

        self.assertIsNone(
            ebsr.normalise_cvss_v31_exploitability(vector)
        )

    def test_invalid_scope_is_not_quantified(self):
        vector = VECTOR.replace("S:U", "S:INVALID")

        self.assertIsNone(
            ebsr.normalise_cvss_v31_exploitability(vector)
        )
        self.assertIsNone(ebsr.calculate_source_impact(vector))

    def test_missing_required_metric_is_not_quantified(self):
        vector = VECTOR.replace("/A:N", "")

        self.assertIsNone(
            ebsr.normalise_cvss_v31_exploitability(vector)
        )

    def test_duplicate_or_invalid_base_metric_is_not_quantified(self):
        duplicate = VECTOR + "/AV:N"
        invalid_attack_vector = VECTOR.replace("AV:N", "AV:INVALID")

        self.assertIsNone(
            ebsr.normalise_cvss_v31_exploitability(duplicate)
        )
        self.assertIsNone(
            ebsr.normalise_cvss_v31_exploitability(
                invalid_attack_vector
            )
        )

    def test_source_impact_uses_cvss_cia_weights(self):
        impact = ebsr.calculate_source_impact(VECTOR)

        self.assertEqual(impact["channels"]["C"], 0.0)
        self.assertEqual(impact["channels"]["I"], 0.56)
        self.assertEqual(impact["channels"]["A"], 0.0)
        self.assertAlmostEqual(
            impact["impact_index"],
            0.612144956,
            places=8
        )


class PathFeasibilityTests(unittest.TestCase):

    def test_false_path_precedes_missing_cvss(self):
        result = ebsr.evaluate_path(
            path(
                "p-false",
                conditions=["failed"],
                vulnerabilities=[
                    vulnerability(vector=None)
                ]
            ),
            {"failed": "F"}
        )

        self.assertEqual(
            result["feasibility"]["status"],
            "ZERO"
        )
        self.assertEqual(
            result["feasibility"]["interval"],
            [0.0, 0.0]
        )

    def test_missing_cvss_is_unquantified(self):
        result = ebsr.evaluate_path(
            path(
                "p-missing",
                conditions=["supported"],
                vulnerabilities=[
                    vulnerability(vector=None)
                ]
            ),
            {"supported": "T"}
        )

        self.assertEqual(
            result["feasibility"]["status"],
            "UNQUANTIFIED"
        )
        self.assertIsNone(
            result["feasibility"]["interval"]
        )

    def test_invalid_cvss_precedence_preserves_false_and_conflict(self):
        invalid_vector = VECTOR.replace("S:U", "S:INVALID")
        false_result = ebsr.evaluate_path(
            path(
                "p-invalid-false",
                conditions=["failed"],
                vulnerabilities=[
                    vulnerability(vector=invalid_vector)
                ]
            ),
            {"failed": "F"}
        )
        conflict_result = ebsr.evaluate_path(
            path(
                "p-invalid-conflict",
                conditions=["conflict"],
                vulnerabilities=[
                    vulnerability(vector=invalid_vector)
                ]
            ),
            {"conflict": "X"}
        )
        unknown_result = ebsr.evaluate_path(
            path(
                "p-invalid-unknown",
                conditions=["unknown"],
                vulnerabilities=[
                    vulnerability(vector=invalid_vector)
                ]
            ),
            {"unknown": "U"}
        )

        self.assertEqual(false_result["feasibility"]["status"], "ZERO")
        self.assertEqual(conflict_result["feasibility"]["status"], "X")
        self.assertEqual(
            unknown_result["feasibility"]["status"],
            "UNQUANTIFIED"
        )

    def test_path_without_vulnerability_is_unquantified(self):
        result = ebsr.evaluate_path(
            path(
                "p-action-only",
                conditions=["supported"],
                actions=[
                    {
                        "step_id": "move",
                        "mechanism": "DF",
                        "condition_ids": ["supported"]
                    }
                ]
            ),
            {"supported": "T"}
        )

        self.assertEqual(
            result["feasibility"]["status"],
            "UNQUANTIFIED"
        )

    def test_false_path_without_vulnerability_is_zero(self):
        result = ebsr.evaluate_path(
            path(
                "p-action-false",
                conditions=["failed"],
                actions=[
                    {
                        "step_id": "move",
                        "mechanism": "DF",
                        "condition_ids": ["failed"]
                    }
                ]
            ),
            {"failed": "F"}
        )

        self.assertEqual(
            result["feasibility"]["status"],
            "ZERO"
        )
        self.assertEqual(
            result["feasibility"]["interval"],
            [0.0, 0.0]
        )

    def test_true_and_unknown_gates(self):
        target = {
            "C": channel("c-false"),
            "I": channel("i-unknown"),
            "A": channel("a-false")
        }
        propositions = {
            "supported": "T",
            "unknown": "U",
            "c-false": "F",
            "i-unknown": "U",
            "a-false": "F"
        }

        true_result = ebsr.evaluate_path(
            path(
                "p-true",
                conditions=["supported"],
                vulnerabilities=[vulnerability()],
                channels=target
            ),
            propositions
        )
        unknown_result = ebsr.evaluate_path(
            path(
                "p-unknown",
                conditions=["unknown"],
                vulnerabilities=[vulnerability()],
                channels=target
            ),
            propositions
        )

        self.assertAlmostEqual(
            true_result["feasibility"]["interval"][0],
            0.729411765,
            places=8
        )
        self.assertAlmostEqual(
            unknown_result["feasibility"]["interval"][0],
            0.0
        )
        self.assertAlmostEqual(
            unknown_result["feasibility"]["interval"][1],
            0.729411765,
            places=8
        )

    def test_mixed_path_is_conditional_technical_only(self):
        result = ebsr.evaluate_path(
            path(
                "p-mixed",
                conditions=["supported"],
                vulnerabilities=[vulnerability()],
                actions=[
                    {
                        "step_id": "data-flow",
                        "mechanism": "DF",
                        "condition_ids": ["supported"]
                    }
                ]
            ),
            {"supported": "T"}
        )

        self.assertEqual(
            result["feasibility"]["quantification_scope"],
            "CONDITIONAL_TECHNICAL_EXPLOITABILITY"
        )
        self.assertFalse(
            result["feasibility"][
                "complete_path_feasibility_quantified"
            ]
        )

    def test_multiple_vulnerabilities_use_technical_bottleneck(self):
        lower_vector = (
            "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:H/A:N"
        )
        result = ebsr.evaluate_path(
            path(
                "p-two-cves",
                conditions=["supported"],
                vulnerabilities=[
                    vulnerability("CVE-1", VECTOR),
                    vulnerability("CVE-2", lower_vector)
                ]
            ),
            {"supported": "T"}
        )

        expected = ebsr.normalise_cvss_v31_exploitability(
            lower_vector
        )

        self.assertEqual(
            result["feasibility"]["interval"],
            [expected, expected]
        )


class TargetImpactTests(unittest.TestCase):

    def test_target_channel_evidence_rules(self):
        impact = ebsr.evaluate_target_impact(
            {
                "C": channel("false"),
                "I": channel("unknown"),
                "A": channel("missing-magnitude")
            },
            {
                "false": "F",
                "unknown": "U",
                "missing-magnitude": "T"
            }
        )

        self.assertEqual(impact["C"]["status"], "F")
        self.assertEqual(
            impact["C"]["interval"],
            [0.0, 0.0]
        )
        self.assertEqual(impact["I"]["status"], "U")
        self.assertEqual(
            impact["I"]["interval"],
            [0.0, 1.0]
        )
        self.assertEqual(
            impact["A"]["status"],
            "UNQUANTIFIED"
        )

    def test_true_channel_with_magnitude_is_quantified(self):
        impact = ebsr.evaluate_target_impact(
            {
                "I": channel("affected", [0.22, 0.56])
            },
            {"affected": "T"}
        )

        self.assertEqual(
            impact["I"],
            {
                "status": "QUANTIFIED",
                "interval": [0.22, 0.56],
                "proposition_id": "affected"
            }
        )

    def test_true_channel_with_nonpositive_magnitude_is_unquantified(self):
        impact = ebsr.evaluate_target_impact(
            {
                "I": channel("affected", [0.0, 0.0])
            },
            {"affected": "T"}
        )

        self.assertEqual(
            impact["I"]["status"],
            "UNQUANTIFIED"
        )
        self.assertIsNone(impact["I"]["interval"])

    def test_conflict_channel_remains_conflict(self):
        impact = ebsr.evaluate_target_impact(
            {
                "I": channel("conflicting")
            },
            {"conflicting": "X"}
        )

        self.assertEqual(impact["I"]["status"], "X")
        self.assertIsNone(impact["I"]["interval"])

    def test_source_impact_is_not_copied_to_receiving_component(self):
        result = ebsr.evaluate_path(
            path(
                "p-downstream",
                conditions=["supported"],
                vulnerabilities=[vulnerability()],
                actions=[
                    {
                        "step_id": "mqtt-to-ditto",
                        "mechanism": "DF",
                        "condition_ids": ["path-unknown"]
                    }
                ],
                channels={
                    "C": channel("ditto-C"),
                    "I": channel("ditto-I"),
                    "A": channel("ditto-A")
                }
            ),
            {
                "supported": "T",
                "path-unknown": "U",
                "ditto-C": "U",
                "ditto-I": "U",
                "ditto-A": "U"
            }
        )

        self.assertEqual(
            result["target_impact"]["I"]["interval"],
            [0.0, 1.0]
        )
        self.assertNotEqual(
            result["target_impact"]["I"]["interval"],
            [0.0, 0.56]
        )


class ScenarioAndAggregationTests(unittest.TestCase):

    def _profile(self, feasibility, integrity):
        return {
            "feasibility_interval": feasibility,
            "impact_intervals": {
                "C": [0.0, 0.0],
                "I": integrity,
                "A": [0.0, 0.0]
            }
        }

    def test_pareto_dominance_compares_both_bounds_and_all_channels(self):
        stronger = self._profile([0.7, 0.9], [0.5, 0.7])
        weaker = self._profile([0.6, 0.8], [0.4, 0.7])

        self.assertTrue(
            ebsr.pareto_dominates(stronger, weaker)
        )
        self.assertFalse(
            ebsr.pareto_dominates(weaker, stronger)
        )

    def test_incomparable_profiles_remain_in_pareto_set(self):
        feasibility_heavy = self._profile(
            [0.8, 0.9],
            [0.2, 0.3]
        )
        impact_heavy = self._profile(
            [0.5, 0.7],
            [0.6, 0.8]
        )

        result = ebsr.pareto_max([
            feasibility_heavy,
            impact_heavy
        ])

        self.assertEqual(len(result), 2)

    def test_quantified_feasibility_with_unquantified_impact_is_not_zero(self):
        scenario = {
            "scenario_id": "s-impact-unquantified",
            "attacker_id": "A1",
            "target_component": "Ditto",
            "paths": [
                path(
                    "p-impact-unquantified",
                    conditions=["supported"],
                    vulnerabilities=[vulnerability()],
                    channels={
                        "C": channel("c-false"),
                        "I": channel("i-true-no-magnitude"),
                        "A": channel("a-false")
                    }
                )
            ]
        }

        result = ebsr.evaluate_scenario(
            scenario,
            {
                "supported": "T",
                "c-false": "F",
                "i-true-no-magnitude": "T",
                "a-false": "F"
            }
        )

        self.assertEqual(
            result["status"],
            "PARTIALLY_QUANTIFIED"
        )
        self.assertAlmostEqual(
            result["feasibility_envelope"][0],
            0.729411765,
            places=8
        )
        self.assertEqual(
            result["unquantified_target_impact_paths"],
            [{
                "path_id": "p-impact-unquantified",
                "channels": ["I"]
            }]
        )
        self.assertEqual(len(result["incomplete_profiles"]), 1)
        self.assertIsNone(
            result["incomplete_profiles"][0][
                "impact_intervals"
            ]["I"]
        )

        component = ebsr.aggregate_component(
            [result],
            "Ditto",
            "A1"
        )

        self.assertEqual(
            component["status"],
            "PARTIALLY_QUANTIFIED"
        )
        self.assertAlmostEqual(
            component["feasibility_envelope"][0],
            0.729411765,
            places=8
        )
        self.assertEqual(len(component["incomplete_profiles"]), 1)

    def test_quantified_feasibility_with_conflicting_impact_is_not_zero(self):
        scenario = {
            "scenario_id": "s-impact-conflict",
            "attacker_id": "A1",
            "target_component": "Ditto",
            "paths": [
                path(
                    "p-impact-conflict",
                    conditions=["supported"],
                    vulnerabilities=[vulnerability()],
                    channels={
                        "C": channel("c-false"),
                        "I": channel("i-conflict"),
                        "A": channel("a-false")
                    }
                )
            ]
        }

        result = ebsr.evaluate_scenario(
            scenario,
            {
                "supported": "T",
                "c-false": "F",
                "i-conflict": "X",
                "a-false": "F"
            }
        )

        self.assertEqual(
            result["status"],
            "PARTIALLY_QUANTIFIED"
        )
        self.assertAlmostEqual(
            result["feasibility_envelope"][1],
            0.729411765,
            places=8
        )
        self.assertEqual(
            result["conflict_target_impact_paths"],
            [{
                "path_id": "p-impact-conflict",
                "channels": ["I"]
            }]
        )
        self.assertEqual(len(result["incomplete_profiles"]), 1)

        component = ebsr.aggregate_component(
            [result],
            "Ditto",
            "A1"
        )

        self.assertEqual(
            component["status"],
            "PARTIALLY_QUANTIFIED"
        )
        self.assertAlmostEqual(
            component["feasibility_envelope"][0],
            0.729411765,
            places=8
        )

    def test_incomplete_impact_is_retained_with_fully_quantified_path(self):
        scenario = {
            "scenario_id": "s-mixed-impact",
            "attacker_id": "A1",
            "target_component": "Ditto",
            "paths": [
                path(
                    "p-incomplete",
                    conditions=["supported"],
                    vulnerabilities=[vulnerability()],
                    channels={
                        "C": channel("c-false"),
                        "I": channel("i-true-no-magnitude"),
                        "A": channel("a-false")
                    }
                ),
                path(
                    "p-complete",
                    conditions=["supported"],
                    vulnerabilities=[vulnerability()],
                    channels={
                        "C": channel("c-false"),
                        "I": channel("i-quantified", 0.56),
                        "A": channel("a-false")
                    }
                )
            ]
        }

        result = ebsr.evaluate_scenario(
            scenario,
            {
                "supported": "T",
                "c-false": "F",
                "i-true-no-magnitude": "T",
                "i-quantified": "T",
                "a-false": "F"
            }
        )

        profile_ids = {
            profile["path_id"]
            for profile in result["pareto_profiles"]
        }

        self.assertEqual(
            profile_ids,
            {"p-incomplete", "p-complete"}
        )
        complete = next(
            profile
            for profile in result["pareto_profiles"]
            if profile["path_id"] == "p-complete"
        )
        incomplete = next(
            profile
            for profile in result["pareto_profiles"]
            if profile["path_id"] == "p-incomplete"
        )
        self.assertTrue(complete["pareto_eligible"])
        self.assertFalse(incomplete["pareto_eligible"])

    def test_feasibility_envelope_is_retained_with_incomplete_impact(self):
        scenario = {
            "scenario_id": "s-envelope",
            "attacker_id": "A1",
            "target_component": "InfluxDB",
            "paths": [
                path(
                    "p-envelope",
                    conditions=["supported"],
                    vulnerabilities=[vulnerability()],
                    channels={
                        "C": channel("c-false"),
                        "I": channel("i-true-no-magnitude"),
                        "A": channel("a-false")
                    }
                )
            ]
        }

        result = ebsr.evaluate_scenario(
            scenario,
            {
                "supported": "T",
                "c-false": "F",
                "i-true-no-magnitude": "T",
                "a-false": "F"
            }
        )

        self.assertEqual(
            result["feasibility_envelope"][0],
            result["feasibility_envelope"][1]
        )
        self.assertAlmostEqual(
            result["feasibility_envelope"][0],
            0.729411765,
            places=8
        )
        self.assertEqual(
            result["unquantified_target_impact_paths"][0][
                "channels"
            ],
            ["I"]
        )

    def test_conflict_affects_only_dependent_path(self):
        propositions = {
            "shared-ok": "T",
            "conflicting-edge": "X",
            "clean-edge": "T",
            "c-false": "F",
            "i-unknown": "U",
            "a-false": "F"
        }
        scenario = {
            "scenario_id": "s-conflict",
            "attacker_id": "A1",
            "target_component": "Ditto",
            "paths": [
                path(
                    "p-conflict",
                    conditions=[
                        "shared-ok",
                        "conflicting-edge"
                    ],
                    vulnerabilities=[vulnerability()],
                    channels={
                        "C": channel("c-false"),
                        "I": channel("i-unknown"),
                        "A": channel("a-false")
                    }
                ),
                path(
                    "p-independent",
                    conditions=["shared-ok", "clean-edge"],
                    vulnerabilities=[vulnerability()],
                    channels={
                        "C": channel("c-false"),
                        "I": channel("i-unknown"),
                        "A": channel("a-false")
                    }
                )
            ]
        }

        result = ebsr.evaluate_scenario(
            scenario,
            propositions
        )

        self.assertIn(
            "p-conflict",
            result["conflict_paths"]
        )
        self.assertEqual(
            [profile["path_id"] for profile in result["pareto_profiles"]],
            ["p-independent"]
        )
        self.assertEqual(
            result["paths"][0]["feasibility"]["status"],
            "X"
        )
        self.assertEqual(
            result["paths"][1]["feasibility"]["status"],
            "QUANTIFIED"
        )

    def test_false_paths_do_not_enter_pareto_profiles(self):
        scenario = {
            "scenario_id": "s-zero",
            "attacker_id": "A1",
            "target_component": "Mosquitto",
            "paths": [
                path(
                    "p-false",
                    conditions=["failed"],
                    vulnerabilities=[vulnerability(vector=None)],
                    channels={
                        "C": channel("unknown-C"),
                        "I": channel("unknown-I"),
                        "A": channel("unknown-A")
                    }
                )
            ]
        }

        result = ebsr.evaluate_scenario(
            scenario,
            {
                "failed": "F",
                "unknown-C": "U",
                "unknown-I": "U",
                "unknown-A": "U"
            }
        )

        self.assertEqual(result["status"], "ZERO")
        self.assertEqual(result["pareto_profiles"], [])
        self.assertEqual(
            result["paths"][0]["feasibility"]["interval"],
            [0.0, 0.0]
        )

    def test_blocked_plus_unquantified_alternative_is_partial(self):
        channels = {
            "C": channel("c-false"),
            "I": channel("i-unknown"),
            "A": channel("a-false")
        }
        scenario = {
            "scenario_id": "s-blocked-unquantified",
            "attacker_id": "A1",
            "target_component": "Mosquitto",
            "paths": [
                path(
                    "blocked",
                    conditions=["blocked"],
                    vulnerabilities=[vulnerability()],
                    channels=channels
                ),
                path(
                    "unquantified",
                    conditions=["unresolved"],
                    vulnerabilities=[
                        vulnerability(vector=None)
                    ],
                    channels=channels
                )
            ]
        }

        result = ebsr.evaluate_scenario(
            scenario,
            {
                "blocked": "F",
                "unresolved": "U",
                "c-false": "F",
                "i-unknown": "U",
                "a-false": "F"
            }
        )
        component = ebsr.aggregate_component(
            [result],
            "Mosquitto",
            "A1"
        )

        self.assertEqual(result["status"], "PARTIALLY_QUANTIFIED")
        self.assertEqual(result["feasibility_envelope"], [0.0, 0.0])
        self.assertEqual(result["unquantified_paths"], ["unquantified"])
        self.assertEqual(component["status"], "PARTIALLY_QUANTIFIED")
        self.assertEqual(component["feasibility_envelope"], [0.0, 0.0])

    def test_blocked_plus_conflict_alternative_is_partial(self):
        channels = {
            "C": channel("c-false"),
            "I": channel("i-unknown"),
            "A": channel("a-false")
        }
        scenario = {
            "scenario_id": "s-blocked-conflict",
            "attacker_id": "A1",
            "target_component": "Mosquitto",
            "paths": [
                path(
                    "blocked",
                    conditions=["blocked"],
                    vulnerabilities=[vulnerability()],
                    channels=channels
                ),
                path(
                    "conflict",
                    conditions=["conflict"],
                    vulnerabilities=[vulnerability()],
                    channels=channels
                )
            ]
        }

        result = ebsr.evaluate_scenario(
            scenario,
            {
                "blocked": "F",
                "conflict": "X",
                "c-false": "F",
                "i-unknown": "U",
                "a-false": "F"
            }
        )
        component = ebsr.aggregate_component(
            [result],
            "Mosquitto",
            "A1"
        )

        self.assertEqual(result["status"], "PARTIALLY_QUANTIFIED")
        self.assertEqual(result["feasibility_envelope"], [0.0, 0.0])
        self.assertEqual(result["conflict_paths"], ["conflict"])
        self.assertEqual(component["status"], "PARTIALLY_QUANTIFIED")
        self.assertEqual(component["feasibility_envelope"], [0.0, 0.0])

    def test_all_blocked_alternatives_remain_zero(self):
        channels = {
            "C": channel("c-false"),
            "I": channel("i-false"),
            "A": channel("a-false")
        }
        scenario = {
            "scenario_id": "s-all-blocked",
            "attacker_id": "A1",
            "target_component": "Mosquitto",
            "paths": [
                path(
                    "blocked-a",
                    conditions=["blocked"],
                    vulnerabilities=[vulnerability()],
                    channels=channels
                ),
                path(
                    "blocked-b",
                    conditions=["blocked"],
                    vulnerabilities=[vulnerability()],
                    channels=channels
                )
            ]
        }

        result = ebsr.evaluate_scenario(
            scenario,
            {
                "blocked": "F",
                "c-false": "F",
                "i-false": "F",
                "a-false": "F"
            }
        )
        component = ebsr.aggregate_component(
            [result],
            "Mosquitto",
            "A1"
        )

        self.assertEqual(result["status"], "ZERO")
        self.assertEqual(result["feasibility_envelope"], [0.0, 0.0])
        self.assertEqual(component["status"], "ZERO")

    def test_quantified_plus_unresolved_preserves_envelope(self):
        channels = {
            "C": channel("c-false"),
            "I": channel("i-false"),
            "A": channel("a-false")
        }
        scenario = {
            "scenario_id": "s-quantified-unresolved",
            "attacker_id": "A1",
            "target_component": "Mosquitto",
            "paths": [
                path(
                    "quantified",
                    conditions=["supported"],
                    vulnerabilities=[vulnerability()],
                    channels=channels
                ),
                path(
                    "unresolved",
                    conditions=["unresolved"],
                    vulnerabilities=[vulnerability(vector=None)],
                    channels=channels
                )
            ]
        }

        result = ebsr.evaluate_scenario(
            scenario,
            {
                "supported": "T",
                "unresolved": "U",
                "c-false": "F",
                "i-false": "F",
                "a-false": "F"
            }
        )
        component = ebsr.aggregate_component(
            [result],
            "Mosquitto",
            "A1"
        )

        self.assertEqual(result["status"], "PARTIALLY_QUANTIFIED")
        self.assertAlmostEqual(
            result["feasibility_envelope"][0],
            0.729411765,
            places=8
        )
        self.assertEqual(result["unquantified_paths"], ["unresolved"])
        self.assertEqual(component["status"], "PARTIALLY_QUANTIFIED")
        self.assertAlmostEqual(
            component["feasibility_envelope"][0],
            0.729411765,
            places=8
        )

    def test_component_aggregation_keeps_attackers_separate(self):
        common = {
            "target_component": "Mosquitto",
            "status": "QUANTIFIED",
            "feasibility_envelope": [0.7, 0.8],
            "vulnerability_ids": ["CVE-1"],
            "unquantified_paths": [],
            "conflict_paths": []
        }
        scenario_a = dict(
            common,
            scenario_id="s-a",
            attacker_id="A1",
            pareto_profiles=[
                dict(
                    self._profile([0.7, 0.8], [0.5, 0.6]),
                    scenario_id="s-a",
                    path_id="p-a",
                    attacker_id="A1",
                    target_component="Mosquitto",
                    vulnerability_ids=["CVE-1"],
                    quantification_scope="CVSS_VULNERABILITY_STEPS"
                )
            ]
        )
        scenario_b = dict(
            common,
            scenario_id="s-b",
            attacker_id="A2",
            pareto_profiles=[
                dict(
                    self._profile([0.4, 0.5], [0.3, 0.4]),
                    scenario_id="s-b",
                    path_id="p-b",
                    attacker_id="A2",
                    target_component="Mosquitto",
                    vulnerability_ids=["CVE-2"],
                    quantification_scope="CVSS_VULNERABILITY_STEPS"
                )
            ]
        )

        a1 = ebsr.aggregate_component(
            [scenario_a, scenario_b],
            "Mosquitto",
            "A1"
        )
        system = ebsr.aggregate_system(
            [scenario_a, scenario_b],
            ["Mosquitto"]
        )

        self.assertEqual(
            a1["vulnerability_ids"],
            ["CVE-1"]
        )
        self.assertIn("A1", system["components"]["Mosquitto"])
        self.assertIn("A2", system["components"]["Mosquitto"])

    def test_component_with_no_matching_scenarios_is_unquantified(self):
        result = ebsr.aggregate_component(
            [],
            "InfluxDB",
            "A1"
        )

        self.assertEqual(result["status"], "UNQUANTIFIED")
        self.assertIsNone(result["feasibility_envelope"])

    def test_results_are_json_serialisable(self):
        propositions = {
            "supported": "T",
            "c-false": "F",
            "i-unknown": "U",
            "a-false": "F"
        }
        scenario = {
            "scenario_id": "json-test",
            "attacker_id": "A1",
            "target_component": "Mosquitto",
            "paths": [
                path(
                    "p1",
                    conditions=["supported"],
                    vulnerabilities=[vulnerability()],
                    channels={
                        "C": channel("c-false"),
                        "I": channel("i-unknown"),
                        "A": channel("a-false")
                    }
                )
            ]
        }

        result = ebsr.evaluate_scenario(
            scenario,
            propositions
        )

        json.dumps(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
