"""Build the first evidence-backed IoMT EBSR scenario bundle.

The bundle is generated from the saved 37-record Mosquitto 1.5.5
assessment. It performs no NVD, Docker or filesystem discovery.
"""

import argparse
from copy import deepcopy
import json
from pathlib import Path


REPORT_PATH = Path(
    "output/ebsr_assessments/"
    "ebsr-assessment-20261110T140855977011Z-v1.0.json"
)
DEFAULT_OUTPUT = Path(
    "scenarios/ebsr_mosquitto_12546_12551_v3.json"
)


def load_json(path):
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def cve_assessment_from_report(report):
    source = report["input_evidence"]["cve_assessments"][0]
    affected = deepcopy(source.get("affected", []))
    unknown = deepcopy(source.get("unknown", []))
    not_affected = deepcopy(source.get("not_affected", []))

    if (
        len(affected),
        len(unknown),
        len(not_affected),
    ) != (10, 4, 23):
        raise ValueError(
            "Saved report does not contain the expected "
            "10 affected / 4 unknown / 23 not-affected records."
        )

    for row in affected + unknown + not_affected:
        row["source_snapshot"] = str(REPORT_PATH)

    return {
        "component": "Mosquitto Vulnerable Lab",
        "component_id": "mosquitto",
        "deployment_id": "mosquitto-vuln-lab",
        "display_name": "Mosquitto Vulnerable Lab",
        "version": "1.5.5",
        "detected_version": "1.5.5",
        "assessment_version_source": source.get(
            "assessment_version_source",
            "runtime_probe",
        ),
        "discovery_evidence": {
            "deployment_id": "mosquitto-vuln-lab",
            "component_id": "mosquitto",
            "display_name": "Mosquitto Vulnerable Lab",
            "version": "1.5.5",
            "image": "efrecon/mosquitto:1.5.5",
            "image_id": (
                "sha256:d8bf12824d7fda2811320320dd18931b2f71b9737db91f88aac8be20a1b9bec5"
            ),
            "version_source": "runtime_probe",
            "source_artifact": (
                "output/evidence_runs/"
                "mosquitto_ditto_dataflow_20261109T171754Z.json"
            ),
        },
        "retrieval": deepcopy(source["retrieval"]),
        "retrieval_source": str(REPORT_PATH),
        "affected": affected,
        "affected_other_scale": [],
        "unknown": unknown,
        "not_affected": not_affected,
    }


def proposition(
    proposition_id,
    status,
    evidence_class,
    source,
    evidence,
    reason=None,
):
    return {
        "proposition_id": proposition_id,
        "status": status,
        "evidence_class": evidence_class,
        "source": source,
        "evidence": evidence,
        "reason": reason,
    }


def evidence_set():
    return [
        proposition(
            "cve.2018_12546.applicability",
            "T",
            "SAVED_NVD_CPE_ASSESSMENT",
            REPORT_PATH.as_posix(),
            [
                "Mosquitto 1.5.5 satisfies the NVD CPE range "
                "1.0 through 1.5.5."
            ],
        ),
        proposition(
            "cve.2018_12551.applicability",
            "T",
            "SAVED_NVD_CPE_ASSESSMENT",
            REPORT_PATH.as_posix(),
            [
                "Mosquitto 1.5.5 satisfies the NVD CPE range "
                "1.0 through 1.5.5."
            ],
        ),
        proposition(
            "cve.2018_12546.documented_behaviour",
            "T",
            "DOCUMENTED_VULNERABILITY_BEHAVIOUR",
            "mosquitto_1.5.5_baseline_results.json",
            [
                "NVD description records retained-message delivery "
                "after the publisher's access is revoked."
            ],
        ),
        proposition(
            "cve.2018_12551.documented_behaviour",
            "T",
            "DOCUMENTED_VULNERABILITY_BEHAVIOUR",
            "mosquitto_1.5.5_baseline_results.json",
            [
                "NVD description records that malformed password-file "
                "data is accepted when password-file authentication "
                "is configured."
            ],
        ),
        proposition(
            "attacker.2018_12546.authenticated_publisher",
            "T",
            "HISTORICAL_MANUAL_OBSERVATION",
            "cve_2018_12546_test.py",
            [
                "The controlled case used an authenticated MQTT client "
                "with permission to publish the retained test message."
            ],
        ),
        proposition(
            "configuration.2018_12546.retained_message_and_acl",
            "T",
            "HISTORICAL_MANUAL_OBSERVATION",
            "cve_2018_12546_test.py",
            [
                "The controlled procedure enabled retained messages and "
                "used ACL changes in the isolated experiment."
            ],
        ),
        proposition(
            "transition.mosquitto_to_ditto.historical_delivery",
            "T",
            "HISTORICAL_OBSERVATION",
            (
                "output/evidence_inventories/"
                "iomt_evidence_inventory_20261109T162449Z.json"
            ),
            [
                "Historical broker logs show a Ditto client subscribed "
                "to iomt/vuln-test and receiving retained publications "
                "on 2026-09-16."
            ],
        ),
        proposition(
            "transition.mosquitto_to_ditto.current",
            "U",
            "CURRENT_DEPLOYMENT_EVIDENCE",
            (
                "output/evidence_runs/"
                "mosquitto_ditto_dataflow_20261109T171754Z.json"
            ),
            [
                "The two vulnerable-broker Ditto connections were closed "
                "at the latest collection.",
                "No current MQTT delivery or Thing mutation was observed.",
            ],
            (
                "Historical delivery does not establish the current "
                "connection state."
            ),
        ),
        proposition(
            "transition.ditto_to_influx.current",
            "U",
            "CURRENT_DEPLOYMENT_EVIDENCE",
            (
                "output/evidence_inventories/"
                "iomt_evidence_inventory_20261109T162449Z.json"
            ),
            [
                "No Ditto-to-InfluxDB connector configuration or "
                "observed write was found."
            ],
            "The current data flow is not established.",
        ),
        proposition(
            "capability.2018_12546.direct_retained_access",
            "T",
            "HISTORICAL_MANUAL_OBSERVATION",
            "cve_2018_12546_test.py",
            [
                "The controlled case observed the retained content after "
                "the publisher's write permission was removed."
            ],
        ),
        proposition(
            "transition.direct_mosquitto_2018_12546.current",
            "T",
            "HISTORICAL_MANUAL_OBSERVATION",
            "cve_2018_12546_test.py",
            [
                "The controlled observation targeted the same Mosquitto "
                "deployment and recorded retained-message access."
            ],
        ),
        proposition(
            "receiver.mosquitto.2018_12546.retained_delivery_and_controls",
            "T",
            "HISTORICAL_MANUAL_OBSERVATION",
            "cve_2018_12546_test.py",
            [
                "A new subscriber received the retained message even after "
                "the publisher's ACL access changed."
            ],
        ),
        proposition(
            "capability.2018_12546.transition_to_ditto",
            "U",
            "EVIDENCE_GAP",
            "No cross-component capability evidence",
            [],
            "The retained-message behaviour has not been shown to deliver "
            "affected data across the Mosquitto-to-Ditto transition.",
        ),
        proposition(
            "receiver.ditto.2018_12546.processing_and_controls",
            "U",
            "CURRENT_DEPLOYMENT_EVIDENCE",
            (
                "output/evidence_runs/"
                "mosquitto_ditto_dataflow_20261109T171754Z.json"
            ),
            [
                "The current Ditto connection was closed and ordinary "
                "receiver processing was not observed."
            ],
            "Ditto processing of retained affected data is unknown.",
        ),
        proposition(
            "unresolved.cve_free_step.A_semantics",
            "U",
            "EVIDENCE_GAP",
            "Frozen EBSR definition audit",
            [],
            "The frozen material does not define distinct A evidence for a "
            "CVE-free step; it remains UNKNOWN rather than inheriting B.",
        ),
        proposition(
            "unresolved.cve_free_step.G_semantics",
            "U",
            "EVIDENCE_GAP",
            "Frozen EBSR definition audit",
            [],
            "The frozen material does not define distinct G evidence for a "
            "CVE-free step; it remains UNKNOWN rather than inheriting B.",
        ),
        proposition(
            "deployment.ditto_to_influx.write_prerequisites",
            "U",
            "CURRENT_DEPLOYMENT_EVIDENCE",
            (
                "output/evidence_inventories/"
                "iomt_evidence_inventory_20261109T162449Z.json"
            ),
            [
                "No Ditto-to-InfluxDB connector, bucket or write "
                "configuration was identified."
            ],
            "Deployment prerequisites for the proposed write are unknown.",
        ),
        proposition(
            "capability.ditto_to_influx.vulnerability_effect",
            "U",
            "EVIDENCE_GAP",
            "No vulnerability-capability evidence",
            [],
            "No affected-vulnerability capability is established for a "
            "CVE-free Ditto-to-InfluxDB transition.",
        ),
        proposition(
            "receiver.influxdb.processing_and_controls",
            "U",
            "EVIDENCE_GAP",
            "No receiver-processing evidence",
            [],
            "No evidence establishes InfluxDB authentication, "
            "authorization, validation or processing of Ditto-derived data.",
        ),
        proposition(
            "attacker.2018_12551.actor_and_trigger",
            "U",
            "DOCUMENTED_VULNERABILITY_BEHAVIOUR",
            "mosquitto_1.5.5_baseline_results.json",
            [
                "NVD records the malformed-password-file behaviour but "
                "does not establish who can introduce the malformed data "
                "in this deployment."
            ],
            "Attacker capability and trigger access remain unknown.",
        ),
        proposition(
            "configuration.2018_12551.malformed_password_data",
            "U",
            "CURRENT_DEPLOYMENT_EVIDENCE",
            (
                "output/evidence_runs/"
                "mosquitto_ditto_dataflow_20261109T171754Z.json"
            ),
            [
                "Password-file authentication is configured for the "
                "vulnerable broker.",
                "The password-file contents were not inspected, and no "
                "malformed entry was established."
            ],
            "The vulnerability trigger condition remains unknown.",
        ),
        proposition(
            "capability.2018_12551.direct_vulnerability_effect",
            "U",
            "EVIDENCE_GAP",
            "No deployment-specific validation",
            [],
            "The documented malformed-entry handling has not been "
            "connected to an observed credential or access effect.",
        ),
        proposition(
            "transition.direct_mosquitto_2018_12551.current",
            "U",
            "EVIDENCE_GAP",
            "No direct-effect validation",
            [],
            "No deployment-specific direct effect is established for "
            "CVE-2018-12551.",
        ),
        proposition(
            "receiver.mosquitto.2018_12551.processing_and_controls",
            "U",
            "EVIDENCE_GAP",
            "No receiver-processing evidence",
            [],
            "The vulnerable broker's handling of malformed credential data "
            "and resulting access controls remain unknown.",
        ),
        proposition(
            "capability.2018_12551.transition_to_ditto",
            "U",
            "EVIDENCE_GAP",
            "No transition-capability evidence",
            [],
            "No evidence establishes that CVE-2018-12551 enables or alters "
            "a Mosquitto-to-Ditto transition.",
        ),
        proposition(
            "receiver.ditto.2018_12551.processing_and_controls",
            "U",
            "EVIDENCE_GAP",
            "No receiver evidence",
            [],
            "No evidence links CVE-2018-12551 to a Ditto-specific effect.",
        ),
        proposition(
            "target.mosquitto.12546.C",
            "U",
            "EVIDENCE_GAP",
            "No confidentiality impact magnitude",
            [],
            "The manual observation did not measure confidentiality impact.",
        ),
        proposition(
            "target.mosquitto.12546.I",
            "T",
            "HISTORICAL_MANUAL_OBSERVATION",
            "cve_2018_12546_test.py",
            [
                "Stale retained content remained accessible after ACL change."
            ],
        ),
        proposition(
            "target.mosquitto.12546.A",
            "U",
            "EVIDENCE_GAP",
            "No availability impact magnitude",
            [],
            "The manual observation did not measure availability impact.",
        ),
        proposition(
            "target.ditto.12546.C",
            "U",
            "EVIDENCE_GAP",
            "No downstream evidence",
            [],
        ),
        proposition(
            "target.ditto.12546.I",
            "U",
            "EVIDENCE_GAP",
            "No downstream evidence",
            [],
        ),
        proposition(
            "target.ditto.12546.A",
            "U",
            "EVIDENCE_GAP",
            "No downstream evidence",
            [],
        ),
        proposition(
            "target.influx.12546.C",
            "U",
            "EVIDENCE_GAP",
            "No downstream evidence",
            [],
        ),
        proposition(
            "target.influx.12546.I",
            "U",
            "EVIDENCE_GAP",
            "No downstream evidence",
            [],
        ),
        proposition(
            "target.influx.12546.A",
            "U",
            "EVIDENCE_GAP",
            "No downstream evidence",
            [],
        ),
        proposition(
            "target.mosquitto.12551.C",
            "U",
            "EVIDENCE_GAP",
            "No target-impact evidence",
            [],
        ),
        proposition(
            "target.mosquitto.12551.I",
            "U",
            "EVIDENCE_GAP",
            "No target-impact evidence",
            [],
        ),
        proposition(
            "target.mosquitto.12551.A",
            "U",
            "EVIDENCE_GAP",
            "No target-impact evidence",
            [],
        ),
        proposition(
            "target.ditto.12551.C",
            "U",
            "EVIDENCE_GAP",
            "No downstream evidence",
            [],
        ),
        proposition(
            "target.ditto.12551.I",
            "U",
            "EVIDENCE_GAP",
            "No downstream evidence",
            [],
        ),
        proposition(
            "target.ditto.12551.A",
            "U",
            "EVIDENCE_GAP",
            "No downstream evidence",
            [],
        ),
        proposition(
            "target.influx.12551.C",
            "U",
            "EVIDENCE_GAP",
            "No downstream evidence",
            [],
        ),
        proposition(
            "target.influx.12551.I",
            "U",
            "EVIDENCE_GAP",
            "No downstream evidence",
            [],
        ),
        proposition(
            "target.influx.12551.A",
            "U",
            "EVIDENCE_GAP",
            "No downstream evidence",
            [],
        ),
    ]


def condition(proposition_id):
    return {"proposition_id": proposition_id}


def channels(prefix):
    return {
        channel: condition(f"{prefix}.{channel}")
        for channel in ("C", "I", "A")
    }


def direct_path(cve_id, proposition_prefix, channels_prefix):
    return {
        "path_id": f"{proposition_prefix}-direct",
        "target_deployment_id": "mosquitto-vuln-lab",
        "target_channels": channels(channels_prefix),
        "transitions": [{
            "step_id": f"{proposition_prefix}-direct-step",
            "source_deployment_id": "mosquitto-vuln-lab",
            "target_deployment_id": "mosquitto-vuln-lab",
            "transition_type": "DIRECT",
            "cve_ids": [cve_id],
            "reproduction_grades": {
                cve_id: (
                    "MANUALLY_OBSERVED"
                    if cve_id == "CVE-2018-12546"
                    else "NOT_TESTED"
                )
            },
            "conditions": {
                "A": condition(
                    f"cve.{proposition_prefix}.applicability"
                ),
                "G": condition(
                    (
                        "attacker.2018_12546.authenticated_publisher"
                        if cve_id == "CVE-2018-12546"
                        else "attacker.2018_12551.actor_and_trigger"
                    )
                ),
                "H": condition(
                    (
                        "configuration.2018_12546.retained_message_and_acl"
                        if cve_id == "CVE-2018-12546"
                        else "configuration.2018_12551.malformed_password_data"
                    )
                ),
                "B": condition(
                    (
                        "transition.direct_mosquitto_2018_12546.current"
                        if cve_id == "CVE-2018-12546"
                        else "transition.direct_mosquitto_2018_12551.current"
                    )
                ),
                "K": condition(
                    (
                        "capability.2018_12546.direct_retained_access"
                        if cve_id == "CVE-2018-12546"
                        else "capability.2018_12551.direct_vulnerability_effect"
                    )
                ),
                "Y": condition(
                    (
                        "receiver.mosquitto.2018_12546.retained_delivery_and_controls"
                        if cve_id == "CVE-2018-12546"
                        else "receiver.mosquitto.2018_12551.processing_and_controls"
                    )
                ),
            },
        }],
    }


def ditto_path(cve_id, proposition_prefix, channels_prefix):
    is_12546 = cve_id == "CVE-2018-12546"
    return {
        "path_id": f"{proposition_prefix}-to-ditto",
        "target_deployment_id": "docker",
        "target_channels": channels(channels_prefix),
        "transitions": [{
            "step_id": f"{proposition_prefix}-mqtt-to-ditto",
            "source_deployment_id": "mosquitto-vuln-lab",
            "target_deployment_id": "docker",
            "transition_type": "DF",
            "relationship_id": "relationship.mosquitto-to-ditto",
            "cve_ids": [cve_id],
            "reproduction_grades": {
                cve_id: (
                    "MANUALLY_OBSERVED"
                    if is_12546
                    else "NOT_TESTED"
                )
            },
            "conditions": {
                "A": condition(
                    f"cve.{proposition_prefix}.applicability"
                ),
                "G": condition(
                    (
                        "attacker.2018_12546.authenticated_publisher"
                        if is_12546
                        else "attacker.2018_12551.actor_and_trigger"
                    )
                ),
                "H": condition(
                    (
                        "configuration.2018_12546.retained_message_and_acl"
                        if is_12546
                        else "configuration.2018_12551.malformed_password_data"
                    )
                ),
                "B": condition(
                    "transition.mosquitto_to_ditto.current"
                ),
                "K": condition(
                    (
                        "capability.2018_12546.transition_to_ditto"
                        if is_12546
                        else "capability.2018_12551.transition_to_ditto"
                    )
                ),
                "Y": condition(
                    (
                        "receiver.ditto.2018_12546.processing_and_controls"
                        if is_12546
                        else "receiver.ditto.2018_12551.processing_and_controls"
                    )
                ),
            },
        }],
    }


def influx_path(cve_id, proposition_prefix, channels_prefix):
    is_12546 = cve_id == "CVE-2018-12546"
    return {
        "path_id": f"{proposition_prefix}-to-influx",
        "target_deployment_id": "influxdb-lab",
        "target_channels": channels(channels_prefix),
        "transitions": [
            {
                "step_id": f"{proposition_prefix}-mqtt-to-ditto",
                "source_deployment_id": "mosquitto-vuln-lab",
                "target_deployment_id": "docker",
                "transition_type": "DF",
                "relationship_id": "relationship.mosquitto-to-ditto",
                "cve_ids": [cve_id],
                "reproduction_grades": {
                    cve_id: (
                        "MANUALLY_OBSERVED"
                        if is_12546
                        else "NOT_TESTED"
                    )
                },
                "conditions": {
                    "A": condition(
                        f"cve.{proposition_prefix}.applicability"
                    ),
                    "G": condition(
                        (
                            "attacker.2018_12546.authenticated_publisher"
                            if is_12546
                            else "attacker.2018_12551.actor_and_trigger"
                        )
                    ),
                    "H": condition(
                        (
                            "configuration.2018_12546.retained_message_and_acl"
                            if is_12546
                            else "configuration.2018_12551.malformed_password_data"
                        )
                    ),
                    "B": condition(
                        "transition.mosquitto_to_ditto.current"
                    ),
                    "K": condition(
                        (
                            "capability.2018_12546.transition_to_ditto"
                            if is_12546
                            else "capability.2018_12551.transition_to_ditto"
                        )
                    ),
                    "Y": condition(
                        (
                            "receiver.ditto.2018_12546.processing_and_controls"
                            if is_12546
                            else "receiver.ditto.2018_12551.processing_and_controls"
                        )
                    ),
                },
            },
            {
                "step_id": f"{proposition_prefix}-ditto-to-influx",
                "source_deployment_id": "docker",
                "target_deployment_id": "influxdb-lab",
                "transition_type": "DF",
                "relationship_id": "relationship.ditto-to-influx",
                "cve_ids": [],
                "conditions": {
                    "A": condition(
                        "unresolved.cve_free_step.A_semantics"
                    ),
                    "G": condition(
                        "unresolved.cve_free_step.G_semantics"
                    ),
                    "H": condition(
                        "deployment.ditto_to_influx.write_prerequisites"
                    ),
                    "B": condition(
                        "transition.ditto_to_influx.current"
                    ),
                    "K": condition(
                        "capability.ditto_to_influx.vulnerability_effect"
                    ),
                    "Y": condition(
                        "receiver.influxdb.processing_and_controls"
                    ),
                },
            },
        ],
    }


def scenarios():
    return [
        {
            "scenario_id": "RESEARCH-12546-MOSQUITTO",
            "attacker_id": "ATTACKER-AUTHENTICATED-PUBLISHER",
            "target_deployment_id": "mosquitto-vuln-lab",
            "description": (
                "Direct retained-message integrity scenario based on "
                "the manually recorded CVE-2018-12546 observation."
            ),
            "paths": [
                direct_path(
                    "CVE-2018-12546",
                    "2018_12546",
                    "target.mosquitto.12546",
                )
            ],
        },
        {
            "scenario_id": "RESEARCH-12546-DITTO",
            "attacker_id": "ATTACKER-AUTHENTICATED-PUBLISHER",
            "target_deployment_id": "docker",
            "description": (
                "Candidate Mosquitto-to-Ditto path. Current delivery and "
                "receiver processing remain UNKNOWN."
            ),
            "paths": [
                ditto_path(
                    "CVE-2018-12546",
                    "2018_12546",
                    "target.ditto.12546",
                )
            ],
        },
        {
            "scenario_id": "RESEARCH-12546-INFLUX",
            "attacker_id": "ATTACKER-AUTHENTICATED-PUBLISHER",
            "target_deployment_id": "influxdb-lab",
            "description": (
                "Candidate Mosquitto-to-Ditto-to-InfluxDB path. The "
                "second transition carries data without another CVE."
            ),
            "paths": [
                influx_path(
                    "CVE-2018-12546",
                    "2018_12546",
                    "target.influx.12546",
                )
            ],
        },
        {
            "scenario_id": "RESEARCH-12551-MOSQUITTO",
            "attacker_id": "ATTACKER-UNRESOLVED-12551",
            "target_deployment_id": "mosquitto-vuln-lab",
            "description": (
                "Direct malformed-password-file scenario. The trigger and "
                "credential/access effect remain UNKNOWN."
            ),
            "paths": [
                direct_path(
                    "CVE-2018-12551",
                    "2018_12551",
                    "target.mosquitto.12551",
                )
            ],
        },
        {
            "scenario_id": "RESEARCH-12551-DITTO",
            "attacker_id": "ATTACKER-UNRESOLVED-12551",
            "target_deployment_id": "docker",
            "description": (
                "Candidate Mosquitto-to-Ditto path for CVE-2018-12551. "
                "All downstream receiver evidence is UNKNOWN."
            ),
            "paths": [
                ditto_path(
                    "CVE-2018-12551",
                    "2018_12551",
                    "target.ditto.12551",
                )
            ],
        },
        {
            "scenario_id": "RESEARCH-12551-INFLUX",
            "attacker_id": "ATTACKER-UNRESOLVED-12551",
            "target_deployment_id": "influxdb-lab",
            "description": (
                "Candidate Mosquitto-to-Ditto-to-InfluxDB path for "
                "CVE-2018-12551. No downstream transition is established."
            ),
            "paths": [
                influx_path(
                    "CVE-2018-12551",
                    "2018_12551",
                    "target.influx.12551",
                )
            ],
        },
    ]


def build_bundle(report):
    assessment = cve_assessment_from_report(report)

    return {
        "schema_version": "1.1",
        "assessment_version": "research-mosquitto-2026-11-10-v3",
        "assessment_scope": (
            "Mosquitto, Eclipse Ditto and InfluxDB; CVE-2018-12546 "
            "and CVE-2018-12551 only"
        ),
        "evidence_provenance": {
            "historical_cve_source": str(REPORT_PATH),
            "runtime_and_architecture_sources": [
                (
                    "output/evidence_inventories/"
                    "iomt_evidence_inventory_20261109T162449Z.json"
                ),
                (
                    "output/evidence_runs/"
                    "mosquitto_ditto_dataflow_20261109T171754Z.json"
                ),
                "cve_2018_12546_test.py",
                "ditto-message.json",
            ],
            "source_classes": [
                "SAVED_NVD_CPE_ASSESSMENT",
                "DOCUMENTED_VULNERABILITY_BEHAVIOUR",
                "HISTORICAL_MANUAL_OBSERVATION",
                "HISTORICAL_OBSERVATION",
                "CURRENT_DEPLOYMENT_EVIDENCE",
                "EVIDENCE_GAP",
            ],
        },
        "condition_semantics": {
            "H": "Deployment prerequisites",
            "B": "Explicit architecture relationship",
            "K": "Vulnerability capability for the transition",
            "Y": "Receiver processing and receiver controls",
            "target_C_I_A": "Target consequences only",
        },
        "research_decisions": [
            {
                "decision_id": "CVE_FREE_STEP_A_G_UNDEFINED",
                "status": "UNDEFINED_IN_FROZEN_MATERIAL",
                "decision": (
                    "For an order-preserving step with cve_ids set to an "
                    "empty list, the frozen material does not define "
                    "separate A or G evidence semantics. A and G are kept "
                    "UNKNOWN and do not inherit B, H, K or Y."
                ),
            },
            {
                "decision_id": "DITTO_TO_INFLUX_DF",
                "status": "CANDIDATE_ONLY",
                "decision": (
                    "The proposed Ditto-to-InfluxDB write is represented "
                    "as DF with no additional CVE. Its relationship remains "
                    "UNKNOWN until an actual write is verified."
                ),
            },
        ],
        "deployments": [
            {
                "deployment_id": "mosquitto-vuln-lab",
                "component_id": "mosquitto",
                "display_name": "Mosquitto Vulnerable Lab",
                "version": "1.5.5",
                "discovery_evidence": deepcopy(
                    assessment["discovery_evidence"]
                ),
            },
            {
                "deployment_id": "docker",
                "component_id": "ditto",
                "display_name": "Eclipse Ditto",
                "version": "3.9.7",
                "discovery_evidence": {
                    "compose_project": "docker",
                    "services_version": "3.9.7",
                    "source_artifact": (
                        "output/evidence_inventories/"
                        "iomt_evidence_inventory_20261109T162449Z.json"
                    ),
                },
            },
            {
                "deployment_id": "influxdb-lab",
                "component_id": "influxdb",
                "display_name": "InfluxDB",
                "version": "2.7.11",
                "discovery_evidence": {
                    "deployment_id": "influxdb-lab",
                    "image": "influxdb:2.7.11",
                    "runtime_state_at_latest_collection": "exited",
                    "source_artifact": (
                        "output/evidence_inventories/"
                        "iomt_evidence_inventory_20261109T162449Z.json"
                    ),
                },
            },
        ],
        "attacker_profiles": [
            {
                "attacker_id": "ATTACKER-AUTHENTICATED-PUBLISHER",
                "description": (
                    "Authenticated MQTT publisher with topic access used "
                    "in the manually recorded CVE-2018-12546 case."
                ),
                "capabilities": [
                    "authenticated MQTT publish before ACL revocation"
                ],
                "provenance": "cve_2018_12546_test.py",
            },
            {
                "attacker_id": "ATTACKER-UNRESOLVED-12551",
                "description": (
                    "Explicit profile for CVE-2018-12551 whose access to "
                    "introduce malformed password-file data is unresolved."
                ),
                "capabilities": [],
                "provenance": (
                    "NVD description does not establish the required actor "
                    "or write access in this deployment."
                ),
            },
        ],
        "architecture_evidence": [
            {
                "relationship_id": "relationship.mosquitto-to-ditto",
                "source_deployment_id": "mosquitto-vuln-lab",
                "target_deployment_id": "docker",
                "transition_type": "DF",
                "status": "UNKNOWN",
                "evidence": [
                    "Current Ditto connection 709e3efe-... is closed.",
                    "Historical broker logs show a Ditto client receiving "
                    "iomt/vuln-test publications.",
                    "No current connected and processed message was observed."
                ],
                "notes": (
                    "Historical delivery and current configuration are "
                    "retained separately; current B remains UNKNOWN."
                ),
            },
            {
                "relationship_id": "relationship.ditto-to-influx",
                "source_deployment_id": "docker",
                "target_deployment_id": "influxdb-lab",
                "transition_type": "DF",
                "status": "UNKNOWN",
                "evidence": [
                    "No Ditto-to-InfluxDB connector was identified.",
                    "No observed InfluxDB write or current active data path."
                ],
                "notes": (
                    "DF describes the proposed Ditto-to-InfluxDB data "
                    "write. UNKNOWN means no write has been verified."
                ),
            },
        ],
        "evidence": evidence_set(),
        "cve_assessments": [assessment],
        "scenarios": scenarios(),
        "validation_records": [
            {
                "deployment_id": "mosquitto-vuln-lab",
                "cve_id": "CVE-2018-12546",
                "validation_status": "VALIDATED",
                "manually_recorded": True,
                "independently_reproduced": False,
                "evidence": [
                    "A retained message remained accessible after the "
                    "publisher's ACL access was revoked."
                ],
                "source": "cve_2018_12546_test.py",
            }
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Build the evidence-backed Mosquitto EBSR scenario bundle."
    )
    parser.add_argument(
        "--report",
        default=str(REPORT_PATH),
        help="Saved historical assessment report.",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Destination scenario JSON.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Allow replacing an existing scenario bundle.",
    )
    args = parser.parse_args()

    report = load_json(Path(args.report))
    output = Path(args.output)

    if output.exists() and not args.force:
        raise SystemExit(
            f"Refusing to overwrite existing file: {output}"
        )

    bundle = build_bundle(report)
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8") as stream:
        json.dump(bundle, stream, indent=2)
        stream.write("\n")

    print(f"Saved scenario bundle: {output}")
    print(f"Deployments: {len(bundle['deployments'])}")
    print(f"Scenarios: {len(bundle['scenarios'])}")


if __name__ == "__main__":
    main()
