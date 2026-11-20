"""Build the v4 EBSR research bundle from frozen v3 plus lab evidence.

This builder applies only the observations directly supported by the controlled
normal-data-flow run. Broader and CVE-specific v3 propositions remain UNKNOWN.
"""

from __future__ import annotations

import copy
from datetime import datetime
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
V3_PATH = ROOT / "scenarios" / "ebsr_mosquitto_12546_12551_v3.json"
OUTPUT_PATH = ROOT / "scenarios" / "ebsr_mosquitto_12546_12551_v4.json"
EVIDENCE_RUN_ID = "mosquitto-ditto-dataflow-20261115T194146829204Z"
EVIDENCE_PATH = ROOT / "output" / "evidence_runs" / f"{EVIDENCE_RUN_ID}.json"
EVIDENCE_SOURCE = f"output/evidence_runs/{EVIDENCE_RUN_ID}.json"


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def evidence_by_id(document: dict, proposition_id: str) -> dict:
    matches = [
        item
        for item in document.get("evidence", [])
        if item.get("proposition_id") == proposition_id
    ]
    if len(matches) != 1:
        raise ValueError(
            f"Expected one proposition {proposition_id!r}; found {len(matches)}."
        )
    return matches[0]


def validate_evidence_run(run: dict) -> None:
    if run.get("result") != "COMPLETED" or run.get("failure") is not None:
        raise ValueError("The source data-flow run did not complete successfully.")

    route = run.get("route") or {}
    if route.get("connection_id") != "709e3efe-3c62-4e41-9538-dc5316c43efd":
        raise ValueError("The evidence run used an unexpected connection.")
    if route.get("mqtt_source_topic") != "iomt/vuln-test":
        raise ValueError("The evidence run used an unexpected MQTT source topic.")
    if route.get("thing_id") != "iomt:device1":
        raise ValueError("The evidence run targeted an unexpected Thing.")
    if route.get("field_path") != "/attributes/temperature":
        raise ValueError("The evidence run observed an unexpected field.")

    values = run.get("values") or {}
    marker = values.get("marker")
    if not marker or values.get("observed_after") != marker:
        raise ValueError("The unique marker was not read back through the API.")
    if values.get("before") != 38.2 or values.get("idle") != 38.2:
        raise ValueError("The initial/idle field values are inconsistent.")
    if values.get("restored") != 38.2:
        raise ValueError("The target field was not restored.")

    timings = run.get("timings") or {}
    ordered_timestamps = [
        "publish_started_utc",
        "puback_received_utc",
        "field_changed_observed_utc",
    ]
    parsed = [parse_utc(timings[name]) for name in ordered_timestamps]
    if parsed != sorted(parsed):
        raise ValueError("The publish, acknowledgment and readback times disagree.")
    if timings.get("retained") is not False or timings.get("qos") != 1:
        raise ValueError("The evidence run message metadata is unexpected.")

    stages = run.get("stage_results") or {}
    if stages.get("broker_acceptance") != "VERIFIED_BY_PUBACK":
        raise ValueError("Broker acceptance is not supported by PUBACK evidence.")
    if stages.get("ditto_receipt") != "VERIFIED_BY_CONNECTION_OBSERVATION":
        raise ValueError("Ditto receipt is not supported by connection evidence.")
    if stages.get("ditto_processing") != "VERIFIED_BY_THING_MUTATION":
        raise ValueError("Ditto processing is not supported by Thing mutation.")

    cleanup = run.get("cleanup") or {}
    cleanup_checks = [
        "field_restore_verified",
        "policy_restore_verified",
        "connection_restore_verified",
        "acl_restore_verified",
    ]
    if not all(cleanup.get(name) is True for name in cleanup_checks):
        raise ValueError("One or more cleanup checks failed.")
    if (
        cleanup.get("broker_initial_state") != "running"
        or cleanup.get("broker_final_state") != "running"
    ):
        raise ValueError("Broker state was not restored.")

    changes = run.get("changes") or {}
    if changes.get("message_published") is not True:
        raise ValueError("The evidence run does not contain a publication.")
    if changes.get("message_retained") is not False:
        raise ValueError("The evidence run used a retained message.")


def normal_flow_observation(run: dict) -> dict:
    timings = run["timings"]
    values = run["values"]
    return {
        "observation_id": EVIDENCE_RUN_ID,
        "observation_class": "CURRENT_CONTROLLED_NORMAL_DATA_FLOW",
        "source_deployment_id": "mosquitto-vuln-lab",
        "target_deployment_id": "docker",
        "connection_id": run["route"]["connection_id"],
        "test_window_utc": {
            "idle_started": timings["idle_started_utc"],
            "idle_finished": timings["idle_finished_utc"],
            "publish_started": timings["publish_started_utc"],
            "puback_received": timings["puback_received_utc"],
            "field_change_observed": timings["field_changed_observed_utc"],
        },
        "message": {
            "classification": "normal non-retained Ditto Protocol modify",
            "mqtt_source_topic": run["route"]["mqtt_source_topic"],
            "ditto_protocol_topic": run["route"]["payload_topic"],
            "publisher_qos": timings["qos"],
            "retained": timings["retained"],
            "target_thing": run["route"]["thing_id"],
            "target_field": run["route"]["field_path"],
            "marker": values["marker"],
        },
        "observed_results": {
            "broker_acceptance": run["stage_results"]["broker_acceptance"],
            "ditto_receipt": run["stage_results"]["ditto_receipt"],
            "ditto_processing": run["stage_results"]["ditto_processing"],
            "field_before": values["before"],
            "field_after": values["observed_after"],
        },
        "temporary_permissions_and_state": {
            "mqtt_acl": (
                "write iomt/vuln-test temporarily added for the existing "
                "authorized broker user"
            ),
            "ditto_policy": (
                "ditto:inbound-auth-subject temporarily added to the isolated "
                "target policy"
            ),
            "connection": (
                f"{run['route']['connection_id']} temporarily configured with "
                "existing broker credentials and opened"
            ),
            "alternate_connection_preserved": run["route"][
                "alternate_connection_id"
            ],
        },
        "restored_configuration": {
            "field": values["restored"],
            "policy": run["cleanup"]["policy_restore_verified"],
            "connection": run["cleanup"]["connection_restore_verified"],
            "broker_acl": run["cleanup"]["acl_restore_verified"],
            "broker_state": run["cleanup"]["broker_final_state"],
        },
        "limitations": [
            "No CVE was triggered.",
            "The message was non-retained and used normal authorized traffic.",
            "InfluxDB was not involved.",
            "No adverse C/I/A impact or attack feasibility is established.",
        ],
    }


def main() -> Path:
    run = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8-sig"))
    run["route"] = run.get("test_route") or {}
    validate_evidence_run(run)

    document = copy.deepcopy(
        json.loads(V3_PATH.read_text(encoding="utf-8-sig"))
    )
    observation = normal_flow_observation(run)

    document["assessment_version"] = (
        "research-mosquitto-2026-11-10-v4"
    )
    document["derived_from"] = {
        "assessment_version": "research-mosquitto-2026-11-10-v3",
        "path": "scenarios/ebsr_mosquitto_12546_12551_v3.json",
        "frozen_mathematics_changed": False,
    }
    document.setdefault("evidence_provenance", {}).setdefault(
        "runtime_and_architecture_sources", []
    ).append(EVIDENCE_SOURCE)
    document.setdefault("research_decisions", []).append(
        {
            "decision_id": "NORMAL_FLOW_DOES_NOT_ESTABLISH_CVE_PROPAGATION",
            "status": "SCOPE_LIMIT",
            "decision": (
                "The controlled normal non-retained message establishes only "
                "the observed Mosquitto-to-Ditto data path and authorized Ditto "
                "receiver processing. It does not establish CVE-specific "
                "transition capability, retained affected-data processing, "
                "target C/I/A impact, or attack feasibility."
            ),
        }
    )

    relationship = next(
        item
        for item in document["architecture_evidence"]
        if item.get("relationship_id") == "relationship.mosquitto-to-ditto"
    )
    relationship["evidence"].extend(
        [
            (
                f"{EVIDENCE_SOURCE} observed one normal non-retained message "
                "from iomt/vuln-test through connection "
                f"{run['route']['connection_id']} into Ditto."
            ),
            (
                "The message changed the isolated iomt:device1 field "
                "/attributes/temperature and was read back through the Things API."
            ),
            (
                "The connection, ACL, policy and field were restored after the "
                "test; the restored baseline remains a closed connection."
            ),
        ]
    )
    relationship["notes"] = (
        "A controlled current-deployment normal data flow was observed while "
        "the selected connection and minimum permissions were temporarily "
        "enabled. Baseline B remains UNKNOWN after restoration and does not "
        "establish CVE-specific propagation."
    )

    current_flow = evidence_by_id(
        document, "transition.mosquitto_to_ditto.current"
    )
    current_flow["source"] = EVIDENCE_SOURCE
    current_flow["evidence"].extend(
        [
            (
                "One non-retained Ditto Protocol modify message crossed "
                f"{run['route']['mqtt_source_topic']} to "
                f"{run['route']['thing_id']}{run['route']['field_path']} "
                f"over connection {run['route']['connection_id']}."
            ),
            (
                "The current baseline connection is not continuously open: "
                "the temporary connection and permissions were restored."
            ),
        ]
    )
    current_flow["reason"] = (
        "The successful run establishes a controlled normal data path, not a "
        "persistently current CVE path. The v3 current-flow proposition remains "
        "UNKNOWN and the observation is represented separately."
    )

    for proposition_id in (
        "capability.2018_12546.transition_to_ditto",
        "receiver.ditto.2018_12546.processing_and_controls",
        "capability.2018_12551.transition_to_ditto",
        "receiver.ditto.2018_12551.processing_and_controls",
    ):
        proposition = evidence_by_id(document, proposition_id)
        proposition["evidence"].append(
            (
                "The controlled v4 run processed a normal non-retained message "
                "only; it did not exercise the CVE-specific retained or "
                "malformed-credential behavior."
            )
        )
        proposition["reason"] = (
            "A normal authorized data-flow observation cannot establish this "
            "CVE-specific capability or receiver-control proposition."
        )

    document.setdefault("evidence", []).extend(
        [
            {
                "proposition_id": (
                    "observation.mosquitto_to_ditto.normal_dataflow."
                    "20261115T194146829204Z"
                ),
                "status": "T",
                "evidence_class": "CURRENT_CONTROLLED_LAB_OBSERVATION",
                "source": EVIDENCE_SOURCE,
                "evidence": [
                    (
                        "Connection 709e3efe-3c62-4e41-9538-dc5316c43efd "
                        "accepted one current-deployment normal message from "
                        "mosquitto-vuln-lab to Ditto during the recorded run."
                    ),
                    (
                        "The message was published at "
                        f"{run['timings']['publish_started_utc']}, acknowledged "
                        f"at {run['timings']['puback_received_utc']}, consumed "
                        "by the Ditto connection, and associated with one "
                        "successful inbound mapping."
                    ),
                ],
                "reason": None,
                "scope": {
                    "source_deployment_id": "mosquitto-vuln-lab",
                    "target_deployment_id": "docker",
                    "normal_message_only": True,
                    "temporary_permissions_required": True,
                },
            },
            {
                "proposition_id": (
                    "observation.ditto.authorized_processing.normal_message."
                    "20261115T194146829204Z"
                ),
                "status": "T",
                "evidence_class": "CURRENT_CONTROLLED_LAB_OBSERVATION",
                "source": EVIDENCE_SOURCE,
                "evidence": [
                    (
                        "The unique marker "
                        f"{run['values']['marker']} was read from "
                        f"{run['route']['thing_id']}"
                        f"{run['route']['field_path']} at "
                        f"{run['timings']['field_changed_observed_utc']}."
                    ),
                    (
                        "Ditto recorded one successful inbound consume, one "
                        "successful map and one successful policy enforcement "
                        "for the controlled message."
                    ),
                ],
                "reason": None,
                "scope": {
                    "target_deployment_id": "docker",
                    "authorized_normal_processing_only": True,
                    "cve_specific_behavior_exercised": False,
                },
            },
            {
                "proposition_id": (
                    "observation.cleanup.mosquitto_to_ditto."
                    "20261115T194146829204Z"
                ),
                "status": "T",
                "evidence_class": "CURRENT_DEPLOYMENT_CLEANUP_VERIFICATION",
                "source": EVIDENCE_SOURCE,
                "evidence": [
                    (
                        "The target field was restored to 38.2; the policy, "
                        "connection and broker ACL restore checks all passed."
                    ),
                    (
                        "The selected connection returned to closed and the "
                        "vulnerable broker remained running."
                    ),
                ],
                "reason": None,
                "scope": {
                    "restored_connection_id": run["route"]["connection_id"],
                    "restored_broker_state": run["cleanup"]["broker_final_state"],
                },
            },
        ]
    )
    document["observations"] = [observation]
    document.setdefault("validation_records", []).append(
        {
            "validation_id": EVIDENCE_RUN_ID,
            "deployment_id": "mosquitto-vuln-lab",
            "target_deployment_id": "docker",
            "validation_status": "CONTROLLED_NORMAL_DATA_FLOW_OBSERVED",
            "cve_specific": False,
            "message_retained": False,
            "independently_reproduced": False,
            "test_window_utc": observation["test_window_utc"],
            "source": EVIDENCE_SOURCE,
            "cleanup_verified": True,
            "evidence": [
                "Broker acceptance was verified by QoS 1 PUBACK.",
                "Ditto receipt and mapping were verified by connection metrics.",
                "Processing was verified by exact marker readback through the API.",
            ],
        }
    )

    OUTPUT_PATH.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return OUTPUT_PATH


if __name__ == "__main__":
    print(main())
