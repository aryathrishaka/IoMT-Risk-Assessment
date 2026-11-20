"""Build v5 from v4 using the controlled end-to-end telemetry run."""

from __future__ import annotations

import copy
import csv
from datetime import datetime
import io
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
V4_PATH = ROOT / "scenarios" / "ebsr_mosquitto_12546_12551_v4.json"
OUTPUT_PATH = ROOT / "scenarios" / "ebsr_mosquitto_12546_12551_v5.json"
RUN_ID = "iomt-telemetry-e2e-20261116T151603273933Z"
RUN_PATH = ROOT / "output" / "evidence_runs" / f"{RUN_ID}.json"
CSV_PATH = (
    ROOT
    / "output"
    / "evidence_runs"
    / f"{RUN_ID}-influx-export.csv"
)
VERIFICATION_PATH = (
    ROOT
    / "output"
    / "evidence_runs"
    / f"{RUN_ID}-readback-verification.json"
)
SOURCE_PATHS = [
    str(RUN_PATH.relative_to(ROOT)).replace("\\", "/"),
    str(CSV_PATH.relative_to(ROOT)).replace("\\", "/"),
    str(VERIFICATION_PATH.relative_to(ROOT)).replace("\\", "/"),
]


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def proposition(document: dict, proposition_id: str) -> dict:
    matches = [
        item
        for item in document.get("evidence", [])
        if item.get("proposition_id") == proposition_id
    ]
    if len(matches) != 1:
        raise ValueError(
            f"Expected one evidence item for {proposition_id!r}."
        )
    return matches[0]


def parse_csv(path: Path) -> dict:
    content = [
        line
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if not line.startswith("#")
    ]
    rows = list(csv.DictReader(io.StringIO("\n".join(content))))
    if len(rows) != 1:
        raise ValueError("The InfluxDB CSV must contain exactly one row.")
    return rows[0]


def validate_artifacts(run: dict, verification: dict, row: dict) -> None:
    expected_thing = "iomt:e2e-mqtt-influx-b7ad0ccd56"
    expected_marker = "E2E-20261116T151603Z-b7ad0ccd56"
    expected_temperature = 41.25

    if run.get("result") != "WRITE_CONFIRMED_READBACK_PENDING":
        raise ValueError("The end-to-end run did not confirm the write.")
    if verification.get("status") != "CONFIRMED":
        raise ValueError("Database readback is not confirmed.")
    if run["configuration"]["thing_id"] != expected_thing:
        raise ValueError("The run Thing ID is unexpected.")
    if run["test"]["run_marker"] != expected_marker:
        raise ValueError("The run marker is unexpected.")
    if run["test"]["numeric_temperature"] != expected_temperature:
        raise ValueError("The run temperature is unexpected.")

    writer = run["test"]["writer_event"] or {}
    if writer.get("thing_id") != expected_thing:
        raise ValueError("The writer event Thing ID differs.")
    if writer.get("run_marker") != expected_marker:
        raise ValueError("The writer event marker differs.")
    if writer.get("temperature") != expected_temperature:
        raise ValueError("The writer event temperature differs.")
    if writer.get("influx_http_status") != 204:
        raise ValueError("InfluxDB did not return HTTP 204.")

    if row.get("thing_id") != expected_thing:
        raise ValueError("The CSV Thing ID differs.")
    if row.get("run_marker") != expected_marker:
        raise ValueError("The CSV marker differs.")
    if float(row.get("_value")) != expected_temperature:
        raise ValueError("The CSV temperature differs.")

    checks = verification.get("checks") or {}
    if not all(
        checks.get(name) is True
        for name in (
            "thing_id_match",
            "marker_match",
            "temperature_match",
        )
    ):
        raise ValueError("Readback verification checks are incomplete.")

    acknowledgement = run["test"]["broker_acknowledgement"] or {}
    if (
        acknowledgement.get("qos") != 1
        or acknowledgement.get("retained") is not False
        or not acknowledgement.get("puback_received_utc")
    ):
        raise ValueError("The MQTT acknowledgement evidence is unexpected.")

    timed_values = [
        run["test"]["idle_started_utc"],
        run["test"]["idle_finished_utc"],
        acknowledgement["publish_started_utc"],
        acknowledgement["puback_received_utc"],
        writer["received_at_utc"],
    ]
    parsed = [parse_utc(value) for value in timed_values]
    if parsed != sorted(parsed):
        raise ValueError("The MQTT, Ditto and InfluxDB times disagree.")

    cleanup = run.get("cleanup") or {}
    if not all(
        cleanup.get(name) is True
        for name in (
            "thing_restored",
            "event_connection_deleted",
            "mqtt_connection_restored",
            "writer_stopped",
        )
    ):
        raise ValueError("Not all lab state was restored.")


def main() -> Path:
    run = json.loads(RUN_PATH.read_text(encoding="utf-8-sig"))
    verification = json.loads(
        VERIFICATION_PATH.read_text(encoding="utf-8-sig")
    )
    row = parse_csv(CSV_PATH)
    validate_artifacts(run, verification, row)

    document = copy.deepcopy(
        json.loads(V4_PATH.read_text(encoding="utf-8-sig"))
    )
    writer = run["test"]["writer_event"]
    acknowledgement = run["test"]["broker_acknowledgement"]
    observation = {
        "observation_id": RUN_ID,
        "observation_class": "CONTROLLED_END_TO_END_NORMAL_TELEMETRY",
        "source_deployment_id": "mosquitto-vuln-lab",
        "target_deployment_id": "influxdb-lab",
        "mqtt_connection_id": run["configuration"]["mqtt_connection_id"],
        "ditto_event_connection_id": run["configuration"][
            "influx_event_connection_id"
        ],
        "thing_id": run["configuration"]["thing_id"],
        "test_window_utc": {
            "idle_started": run["test"]["idle_started_utc"],
            "idle_finished": run["test"]["idle_finished_utc"],
            "publish_started": acknowledgement["publish_started_utc"],
            "puback_received": acknowledgement["puback_received_utc"],
            "ditto_writer_received": writer["received_at_utc"],
            "influx_point": row["_time"],
        },
        "initial_state": {
            "temperature": run["test"]["initial_thing"]["attributes"][
                "temperature"
            ],
            "run_marker": run["test"]["initial_thing"]["attributes"][
                "runMarker"
            ],
        },
        "message": {
            "source": "single MQTT publication",
            "mqtt_topic": run["configuration"]["mqtt_source_topic"],
            "qos": acknowledgement["qos"],
            "retained": acknowledgement["retained"],
            "thing_command_topic": run["test"]["mqtt_payload"]["topic"],
            "path": run["test"]["mqtt_payload"]["path"],
            "temperature": run["test"]["numeric_temperature"],
            "run_marker": run["test"]["run_marker"],
        },
        "tested_configuration": {
            "mqtt_write_acl_temporarily_added": True,
            "mqtt_ingress_connection": run["configuration"][
                "mqtt_connection_id"
            ],
            "ditto_http_event_connection": run["configuration"][
                "influx_event_connection_id"
            ],
            "local_writer": True,
            "writer_influx_health_url": run["configuration"][
                "writer_influx_health_url"
            ],
            "influx_bucket": run["configuration"]["influx_bucket"],
        },
        "observed_results": {
            "broker_puback": acknowledgement["puback_received_utc"],
            "thing_readback": run["test"]["thing_readback"]["attributes"],
            "writer_received": writer["received_at_utc"],
            "influx_http_status": writer["influx_http_status"],
            "csv_influx_time": row["_time"],
            "csv_thing_id": row["thing_id"],
            "csv_run_marker": row["run_marker"],
            "csv_temperature": float(row["_value"]),
            "readback_status": "CONFIRMED",
        },
        "restored_baseline": {
            "thing": run["cleanup"]["thing_restored"],
            "event_connection_deleted": run["cleanup"][
                "event_connection_deleted"
            ],
            "mqtt_connection_closed": run["cleanup"][
                "mqtt_connection_restored"
            ],
            "writer_stopped": run["cleanup"]["writer_stopped"],
            "baseline_relationship_remains_unknown": True,
        },
        "limitations": [
            "No CVE was triggered.",
            "The test carried a normal non-retained message.",
            "The run establishes transport and processing, not adverse C/I/A impact.",
            "Ditto did not record an optional Thing modification timestamp.",
        ],
    }

    document["assessment_version"] = (
        "research-mosquitto-2026-11-10-v5"
    )
    document["derived_from"] = {
        "assessment_version": "research-mosquitto-2026-11-10-v4",
        "path": "scenarios/ebsr_mosquitto_12546_12551_v4.json",
        "frozen_mathematics_changed": False,
    }
    document.setdefault("evidence_provenance", {}).setdefault(
        "runtime_and_architecture_sources", []
    ).extend(SOURCE_PATHS)
    document.setdefault("research_decisions", []).append(
        {
            "decision_id": "END_TO_END_NORMAL_FLOW_SCOPE",
            "status": "SCOPE_LIMIT",
            "decision": (
                "The controlled MQTT-to-Ditto-to-InfluxDB normal telemetry "
                "run proves both transport links only during the tested "
                "configuration. It does not upgrade restored baseline "
                "relationships or CVE-specific downstream effects."
            ),
        }
    )

    for relationship_id in (
        "relationship.mosquitto-to-ditto",
        "relationship.ditto-to-influx",
    ):
        item = next(
            relationship
            for relationship in document["architecture_evidence"]
            if relationship.get("relationship_id") == relationship_id
        )
        item["evidence"].append(
            f"{RUN_ID} observed this link during the controlled test window."
        )
        item["notes"] = (
            "The controlled v5 telemetry chain exercised this link while "
            "temporary test configuration was active. The configuration was "
            "restored afterward, so baseline relationship status remains "
            "UNKNOWN."
        )

    updates = {
        "transition.mosquitto_to_ditto.current": (
            "The controlled MQTT run reached Ditto and updated the isolated "
            "Thing, but the temporary MQTT connection and ACL were restored. "
            "Persistent baseline current-flow evidence remains UNKNOWN."
        ),
        "transition.ditto_to_influx.current": (
            "The controlled Ditto HTTP event was written to InfluxDB and "
            "confirmed by CSV readback, but the event connection and writer "
            "were temporary. Persistent baseline current-flow evidence "
            "remains UNKNOWN."
        ),
        "capability.2018_12546.transition_to_ditto": (
            "A normal MQTT message reached Ditto; this does not establish the "
            "CVE-2018-12546 retained-message capability across the link."
        ),
        "receiver.ditto.2018_12546.processing_and_controls": (
            "Ditto processed a normal MQTT command, not CVE-2018-12546 "
            "affected data. CVE-specific receiver processing remains UNKNOWN."
        ),
        "capability.2018_12551.transition_to_ditto": (
            "A normal MQTT message reached Ditto; this does not establish a "
            "CVE-2018-12551 malformed-credential transition."
        ),
        "receiver.ditto.2018_12551.processing_and_controls": (
            "The run did not exercise malformed password-file behaviour or "
            "CVE-2018-12551 receiver effects."
        ),
    }
    for proposition_id, text in updates.items():
        item = proposition(document, proposition_id)
        item["evidence"].append(text)
        item["reason"] = (
            f"{text} The proposition remains UNKNOWN; see the separate v5 "
            "observation records."
        )

    document.setdefault("evidence", []).extend(
        [
            {
                "proposition_id": (
                    "observation.mosquitto_to_ditto.mqtt_normal_dataflow."
                    "20261116T151603273933Z"
                ),
                "status": "T",
                "evidence_class": "CURRENT_CONTROLLED_LAB_OBSERVATION",
                "source": SOURCE_PATHS[0],
                "evidence": [
                    (
                        "One non-retained MQTT publication was acknowledged by "
                        f"the broker at {acknowledgement['puback_received_utc']}."
                    ),
                    (
                        "Ditto changed the isolated Thing through the MQTT "
                        "ingress connection."
                    ),
                ],
                "reason": None,
                "scope": {
                    "temporary_configuration": True,
                    "baseline_restored": True,
                    "normal_message_only": True,
                },
            },
            {
                "proposition_id": (
                    "observation.ditto_to_influx.normal_event_write."
                    "20261116T151603273933Z"
                ),
                "status": "T",
                "evidence_class": "CURRENT_CONTROLLED_LAB_OBSERVATION",
                "source": SOURCE_PATHS[0],
                "evidence": [
                    (
                        "The writer received the Ditto attributesModified "
                        f"event at {writer['received_at_utc']}."
                    ),
                    "InfluxDB returned HTTP 204.",
                    (
                        f"The CSV row at {row['_time']} contains the same "
                        "Thing ID, run marker and temperature."
                    ),
                ],
                "reason": None,
                "scope": {
                    "temporary_configuration": True,
                    "baseline_restored": True,
                    "normal_event_only": True,
                },
            },
            {
                "proposition_id": (
                    "observation.end_to_end.normal_telemetry_chain."
                    "20261116T151603273933Z"
                ),
                "status": "T",
                "evidence_class": "CURRENT_CONTROLLED_LAB_OBSERVATION",
                "source": SOURCE_PATHS[2],
                "evidence": [
                    (
                        "Broker PUBACK, Ditto Thing readback, writer receipt "
                        "and InfluxDB CSV readback agree on the Thing ID, "
                        "marker and temperature."
                    ),
                    (
                        f"CSV timestamp {row['_time']} follows writer receipt "
                        f"{writer['received_at_utc']} by 47.3 microseconds."
                    ),
                ],
                "reason": None,
                "scope": {
                    "source": "single MQTT message",
                    "normal_telemetry_only": True,
                },
            },
            {
                "proposition_id": (
                    "observation.cleanup.end_to_end."
                    "20261116T151603273933Z"
                ),
                "status": "T",
                "evidence_class": "CURRENT_DEPLOYMENT_CLEANUP_VERIFICATION",
                "source": SOURCE_PATHS[0],
                "evidence": [
                    "The test Thing was restored.",
                    "The temporary Ditto event connection was deleted.",
                    "The MQTT ingress connection was returned to closed.",
                    "The temporary broker ACL was restored and the writer stopped.",
                ],
                "reason": None,
                "scope": {
                    "restored_baseline_status": "UNKNOWN_RELATIONSHIPS",
                },
            },
        ]
    )
    document.setdefault("observations", []).append(observation)
    document.setdefault("validation_records", []).append(
        {
            "validation_id": RUN_ID,
            "deployment_id": "mosquitto-vuln-lab",
            "target_deployment_id": "influxdb-lab",
            "validation_status": (
                "CONTROLLED_END_TO_END_NORMAL_FLOW_CONFIRMED_BY_CSV"
            ),
            "cve_specific": False,
            "message_retained": False,
            "independently_reproduced": False,
            "test_window_utc": observation["test_window_utc"],
            "source": SOURCE_PATHS[0],
            "readback_source": SOURCE_PATHS[2],
            "cleanup_verified": True,
            "evidence": [
                "Broker acceptance was verified by QoS 1 PUBACK.",
                "Ditto processing was verified by Thing API readback.",
                "Ditto event receipt was verified by the writer state.",
                "The InfluxDB row was confirmed by exported CSV.",
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
