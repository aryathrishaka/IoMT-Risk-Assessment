"""Focused tests for main-workflow applicability integration."""

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import main


def cve_record(cve_id):
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [
                {
                    "lang": "en",
                    "value": f"{cve_id} description"
                }
            ],
            "metrics": {}
        }
    }


def retrieval_result(status="COMPLETE", items=None, error=None):
    items = [] if items is None else items

    return {
        "status": status,
        "items": items,
        "received": len(items),
        "total_results": len(items),
        "error": error
    }


def applicability_result(status, reason):
    return {
        "status": status,
        "reason": reason,
        "component": {},
        "configurations": [],
    }


class MainApplicabilityTests(unittest.TestCase):

    def test_available_software_uses_canonical_nvd_search_terms(self):
        detected = {
            component: {
                "version": "1.0.0",
                "status": "Detected",
                "container": f"{component}-container",
                "image": f"{component}:1.0.0"
            }
            for component in (
                "Mosquitto",
                "Mosquitto Vulnerable Lab",
                "InfluxDB",
                "Eclipse Ditto",
                "Unknown Component"
            )
        }

        with patch.object(
            main,
            "detect_versions",
            return_value=detected
        ):
            available = main.get_available_software()

        self.assertEqual(
            available["Mosquitto"]["software"],
            "mosquitto"
        )
        self.assertEqual(
            available["Mosquitto Vulnerable Lab"]["software"],
            "mosquitto"
        )
        self.assertEqual(
            available["InfluxDB"]["software"],
            "influxdb"
        )
        self.assertEqual(
            available["Eclipse Ditto"]["software"],
            "ditto"
        )
        self.assertEqual(
            available["Unknown Component"]["software"],
            "unknown component"
        )

    def test_vulnerable_lab_searches_mosquitto_but_keeps_component_key(self):
        record = cve_record("CVE-LAB")
        detected = {
            "Mosquitto Vulnerable Lab": {
                "version": "1.5.5",
                "status": "Detected",
                "container": "mosquitto-vuln-lab",
                "image": "eclipse-mosquitto:1.5.5",
                "image_digest": "sha256:evidence",
                "version_source": "runtime_probe",
                "runtime_probe": {
                    "status": "DETECTED",
                    "version": "1.5.5"
                },
                "classification_source": [
                    "runtime_probe_product"
                ]
            }
        }

        with patch.object(
            main,
            "detect_versions",
            return_value=detected
        ):
            available = main.get_available_software()

        search_term = available[
            "Mosquitto Vulnerable Lab"
        ]["software"]

        with patch.object(
            main,
            "search_cves_by_keyword_with_status",
            return_value=retrieval_result(items=[record])
        ) as retrieval:
            with patch.object(
                main,
                "evaluate_applicability",
                return_value=applicability_result(
                    "UNKNOWN",
                    "No CPE vendor/product configured."
                )
            ) as evaluator:
                with redirect_stdout(io.StringIO()):
                    main.get_vulnerabilities(
                        "Mosquitto Vulnerable Lab",
                        search_term,
                        "1.5.5"
                    )

        retrieval.assert_called_once_with(
            "mosquitto",
            results_per_page=100
        )
        evaluator.assert_called_once_with(
            record,
            "Mosquitto Vulnerable Lab",
            "1.5.5"
        )

    def test_generic_deployment_uses_detector_nvd_search_term(self):
        detected = {
            "Mosquitto [lab-1]": {
                "software": "not-used",
                "nvd_search_term": "mosquitto",
                "component_id": "mosquitto",
                "version": "1.5.5",
                "status": "Detected",
                "container": "mosquitto-vuln-lab",
                "image": "eclipse-mosquitto:1.5.5",
                "image_digest": "sha256:evidence",
                "version_source": "runtime_probe",
                "runtime_probe": {
                    "status": "DETECTED",
                    "version": "1.5.5"
                },
                "classification_source": [
                    "runtime_probe_product"
                ]
            }
        }

        with patch.object(
            main,
            "detect_versions",
            return_value=detected
        ):
            available = main.get_available_software()

        self.assertEqual(
            available["Mosquitto [lab-1]"]["software"],
            "mosquitto"
        )
        self.assertEqual(
            available["Mosquitto [lab-1]"]["image_digest"],
            "sha256:evidence"
        )
        self.assertEqual(
            available["Mosquitto [lab-1]"]["version_source"],
            "runtime_probe"
        )
        self.assertEqual(
            available["Mosquitto [lab-1]"][
                "runtime_probe"
            ]["version"],
            "1.5.5"
        )

    def test_unclassified_detection_is_visible_but_not_selectable(self):
        detected = {
            "Mosquitto": {
                "software": "mosquitto",
                "nvd_search_term": "mosquitto",
                "component_id": "mosquitto",
                "version": "2.1.2",
                "status": "Detected",
                "container": "mosquitto-lab",
                "image": "eclipse-mosquitto:2.1.2-alpine",
                "diagnostic": False
            },
            "Unclassified deployment [mosquitto-vuln-lab]": {
                "version": "1.5.5",
                "component_id": None,
                "deployment_id": "mosquitto-vuln-lab",
                "status": "UNCLASSIFIED",
                "container": "mosquitto-vuln-lab",
                "image": "efrecon/mosquitto:1.5.5",
                "reason": "No supported product evidence was found.",
                "diagnostic": True
            }
        }

        with patch.object(
            main,
            "detect_versions",
            return_value=detected
        ):
            available = main.get_available_software()

        self.assertFalse(
            available["Mosquitto"]["diagnostic"]
        )
        self.assertTrue(
            available[
                "Unclassified deployment [mosquitto-vuln-lab]"
            ]["diagnostic"]
        )

    def test_main_displays_diagnostics_without_numbering_them_for_selection(self):
        available = {
            "Mosquitto": {
                "software": "mosquitto",
                "version": "2.1.2",
                "container": "mosquitto-lab",
                "image": "eclipse-mosquitto:2.1.2-alpine",
                "diagnostic": False
            },
            "Unclassified deployment [mosquitto-vuln-lab]": {
                "version": "1.5.5",
                "status": "UNCLASSIFIED",
                "container": "mosquitto-vuln-lab",
                "image": "efrecon/mosquitto:1.5.5",
                "reason": "No supported product evidence was found.",
                "diagnostic": True
            }
        }
        output = io.StringIO()

        with patch.object(
            main,
            "get_available_software",
            return_value=available
        ):
            with patch.object(
                main,
                "get_vulnerabilities",
                return_value=([], [], retrieval_result())
            ):
                with patch(
                    "builtins.input",
                    return_value="1"
                ):
                    with redirect_stdout(output):
                        main.main()

        printed = output.getvalue()
        self.assertIn("Docker Discovery Diagnostics", printed)
        self.assertIn(
            "Unclassified deployment [mosquitto-vuln-lab]",
            printed
        )
        self.assertIn("1. Mosquitto (version 2.1.2)", printed)
        self.assertNotIn(
            "2. Unclassified deployment",
            printed
        )

    def test_main_maps_deployment_to_canonical_applicability_and_architecture(self):
        selected = {
            "Mosquitto [vulnerable]": {
                "software": "mosquitto",
                "applicability_component": "mosquitto",
                "architecture_component": "Mosquitto",
                "version": "1.5.5",
                "container": "mosquitto-vuln-lab",
                "image": "efrecon/mosquitto:1.5.5",
                "diagnostic": False
            }
        }
        record = cve_record("CVE-TEST")

        with patch.object(
            main,
            "get_available_software",
            return_value=selected
        ):
            with patch.object(
                main,
                "get_vulnerabilities",
                return_value=(
                    [record],
                    [],
                    retrieval_result(
                        items=[record]
                    )
                )
            ) as get_vulnerabilities:
                with patch.object(
                    main,
                    "extract_cve_information",
                    return_value={
                        "id": "CVE-TEST",
                        "cvss_version": "3.1",
                        "cvss_score": 7.5,
                        "cvss_vector": None
                    }
                ):
                    with patch.object(
                        main,
                        "assess_cvss",
                        return_value=None
                    ):
                        with patch.object(
                            main,
                            "get_attack_path",
                            return_value=["Mosquitto"]
                        ) as get_path:
                            with patch.object(
                                main,
                                "assess_propagation",
                                return_value={
                                    "status": "INSUFFICIENT_EVIDENCE",
                                    "propagation_score": None,
                                    "explanation": "No architecture evidence."
                                }
                            ):
                                with patch(
                                    "builtins.input",
                                    side_effect=["1", "1"]
                                ):
                                    with redirect_stdout(io.StringIO()):
                                        main.main()

        get_vulnerabilities.assert_called_once_with(
            "mosquitto",
            "mosquitto",
            "1.5.5"
        )
        get_path.assert_called_once_with("Mosquitto")

    def test_get_vulnerabilities_uses_exact_component_and_search_inputs(self):
        record = cve_record("CVE-TEST-1")

        with patch.object(
            main,
            "search_cves_by_keyword_with_status",
            return_value=retrieval_result(items=[record])
        ) as retrieval:
            with patch.object(
                main,
                "evaluate_applicability",
                return_value=applicability_result(
                    "AFFECTED",
                    "Affected configuration."
                )
            ) as evaluator:
                with redirect_stdout(io.StringIO()):
                    main.get_vulnerabilities(
                        "Eclipse Ditto",
                        "ditto",
                        "3.9.7"
                    )

        retrieval.assert_called_once_with(
            "ditto",
            results_per_page=100
        )
        evaluator.assert_called_once_with(
            record,
            "Eclipse Ditto",
            "3.9.7"
        )

    def test_affected_unknown_and_not_affected_are_separated(self):
        affected_record = cve_record("CVE-AFFECTED")
        unknown_record = cve_record("CVE-UNKNOWN")
        excluded_record = cve_record("CVE-NOT-AFFECTED")

        with patch.object(
            main,
            "search_cves_by_keyword_with_status",
            return_value=retrieval_result(
                items=[
                    affected_record,
                    unknown_record,
                    excluded_record
                ]
            )
        ):
            with patch.object(
                main,
                "evaluate_applicability",
                side_effect=[
                    applicability_result(
                        "AFFECTED",
                        "Version is in the affected range."
                    ),
                    applicability_result(
                        "UNKNOWN",
                        "Platform condition is not established."
                    ),
                    applicability_result(
                        "NOT_AFFECTED",
                        "Version is outside the affected range."
                    )
                ]
            ):
                with redirect_stdout(io.StringIO()):
                    affected, unknown, retrieval = (
                        main.get_vulnerabilities(
                            "Mosquitto",
                            "mosquitto",
                            "1.5.5"
                        )
                    )

        self.assertEqual(affected, [affected_record])
        self.assertEqual(len(unknown), 1)
        self.assertEqual(unknown[0]["item"], unknown_record)
        self.assertEqual(unknown[0]["status"], "UNKNOWN")
        self.assertEqual(
            unknown[0]["reason"],
            "Platform condition is not established."
        )
        self.assertNotIn(unknown_record, affected)
        self.assertNotIn(excluded_record, affected)
        self.assertEqual(retrieval["status"], "COMPLETE")
        self.assertEqual(
            [
                record["status"]
                for record in retrieval["applicability"]
            ],
            ["AFFECTED", "UNKNOWN", "NOT_AFFECTED"]
        )

    def test_unsupported_component_remains_unknown(self):
        record = cve_record("CVE-LAB")

        with patch.object(
            main,
            "search_cves_by_keyword_with_status",
            return_value=retrieval_result(items=[record])
        ):
            with redirect_stdout(io.StringIO()):
                affected, unknown, retrieval = (
                    main.get_vulnerabilities(
                        "Mosquitto Vulnerable Lab",
                    "mosquitto",
                        "1.5.5"
                    )
                )

        self.assertEqual(affected, [])
        self.assertEqual(len(unknown), 1)
        self.assertEqual(unknown[0]["status"], "UNKNOWN")
        self.assertIn(
            "No CPE vendor/product configured for "
            "Mosquitto Vulnerable Lab",
            unknown[0]["reason"]
        )
        self.assertEqual(retrieval["status"], "COMPLETE")

    def test_unknown_output_is_explicit_and_not_confirmed(self):
        unknown = [{
            "item": cve_record("CVE-UNKNOWN"),
            "status": "UNKNOWN",
            "reason": "NVD has no CPE configuration."
        }]
        output = io.StringIO()

        with redirect_stdout(output):
            main.show_unknown_vulnerabilities(unknown)

        printed = output.getvalue()
        self.assertIn("UNKNOWN Applicability", printed)
        self.assertIn("CVE-UNKNOWN", printed)
        self.assertIn("NVD has no CPE configuration.", printed)
        self.assertIn("not confirmed as affecting", printed)

    def test_main_call_site_passes_exact_component_and_search_term(self):
        detected = {
            "Eclipse Ditto": {
                "software": "ditto",
                "version": "3.9.7",
                "container": "docker-things-1",
                "image": "eclipse/ditto-things:3.9.7",
                "component_id": "ditto",
                "display_name": "Eclipse Ditto",
                "architecture_component": "Eclipse Ditto"
            }
        }

        with patch.object(
            main,
            "get_available_software",
            return_value=detected
        ):
            with patch.object(
                main,
                "get_vulnerabilities",
                return_value=(
                    [],
                    [],
                    retrieval_result()
                )
            ) as get_vulnerabilities:
                with patch(
                    "builtins.input",
                    return_value="1"
                ):
                    with redirect_stdout(io.StringIO()):
                        main.main()

        get_vulnerabilities.assert_called_once_with(
            "ditto",
            "ditto",
            "3.9.7"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
