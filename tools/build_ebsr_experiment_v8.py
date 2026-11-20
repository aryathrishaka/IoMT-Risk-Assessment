"""Build the experiment-scoped v8 EBSR evidence bundle."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
V7_PATH = ROOT / "scenarios" / "ebsr_mosquitto_12546_12550_12551_v7.json"
EXPERIMENT_1_PATH = (
    ROOT
    / "output"
    / "evidence_runs"
    / "cve-2018-12546-retained-acl-20261118T195233320714Z.json"
)
EXPERIMENT_2_PATH = (
    ROOT
    / "output"
    / "evidence_runs"
    / "cve-2018-12546-downstream-20261118T200923198752Z.json"
)
READBACK_PATH = (
    ROOT
    / "output"
    / "evidence_runs"
    / "cve-2018-12546-downstream-20261118T200923198752Z-readback.json"
)
EBSR_PATH = ROOT / "ebsr.py"
ADAPTER_PATH = ROOT / "ebsr_adapter.py"
OUTPUT_PATH = (
    ROOT / "scenarios" / "ebsr_cve_2018_12546_experiment_v8.json"
)

CVE_ID = "CVE-2018-12546"
VULNERABLE_DEPLOYMENT_ID = "iomt-cve12546-down-vulnerable-00e1c6ba6c"
CONTROL_DEPLOYMENT_ID = "iomt-cve12546-down-control-c4c0a63d22"
EXPERIMENT_1_VULNERABLE_ID = "iomt-cve12546-vuln-b7c3ae4e"
EXPERIMENT_1_CONTROL_ID = "iomt-cve12546-control-28ae20e7"
DITTO_DEPLOYMENT_ID = "docker-connectivity-1"
INFLUX_DEPLOYMENT_ID = "influxdb-lab"


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def readback_rows(record: dict, field: str) -> list[dict]:
    return copy.deepcopy(record[field]["rows"])


def evidence_item(
    proposition_id: str,
    status: str,
    evidence_class: str,
    source: str,
    observations: list[str],
    reason: str,
    *,
    scope: str,
) -> dict:
    return {
        "proposition_id": proposition_id,
        "status": status,
        "evidence_class": evidence_class,
        "source": source,
        "evidence": observations,
        "reason": reason,
        "scope": scope,
    }


def target_channel(
    state: str,
    evidence_class: str,
    source: str,
    observations: list[str],
    reason: str,
    *,
    scope: str,
    magnitude=None,
) -> dict:
    value = {
        "state": state,
        "evidence_class": evidence_class,
        "source": source,
        "evidence": observations,
        "reason": reason,
        "scope": scope,
    }
    if magnitude is not None:
        value["magnitude"] = magnitude
    return value


def condition(proposition_id: str) -> dict:
    return {"proposition_id": proposition_id}


def scenario_conditions(
    *,
    arm: str,
    first_step: str,
) -> dict:
    prefix = f"{arm}"
    return {
        "A": condition(
            f"cve.2018_12546.exp2.{prefix}.applicability"
        ),
        "G": condition(
            f"attacker.2018_12546.exp2.{prefix}.authenticated_publisher"
        ),
        "H": condition(
            f"preconditions.2018_12546.exp2.{prefix}.broker_configuration"
        ),
        "B": condition(
            f"architecture.2018_12546.exp2.{prefix}.{first_step}"
        ),
        "K": condition(
            f"capability.2018_12546.exp2.{prefix}.retained_command"
        ),
        "Y": condition(
            f"receiver.ditto.2018_12546.exp2.{prefix}.retained_processing"
        ),
    }


def direct_conditions(arm: str) -> dict:
    return {
        "A": condition(
            f"cve.2018_12546.exp1.{arm}.applicability"
        ),
        "G": condition(
            f"attacker.2018_12546.exp1.{arm}.authenticated_publisher"
        ),
        "H": condition(
            f"preconditions.2018_12546.exp1.{arm}.broker_configuration"
        ),
        "B": condition(
            f"architecture.2018_12546.exp1.{arm}.direct"
        ),
        "K": condition(
            f"capability.2018_12546.exp1.{arm}.retained_command"
        ),
        "Y": condition(
            f"receiver.mosquitto.2018_12546.exp1.{arm}.retained_delivery"
        ),
    }


def cve_free_conditions(arm: str) -> dict:
    return {
        "A": condition("unresolved.2018_12546.cve_free_step.A"),
        "G": condition("unresolved.2018_12546.cve_free_step.G"),
        "H": condition(
            f"preconditions.2018_12546.exp2.{arm}.ditto_to_influx_write"
        ),
        "B": condition(
            f"architecture.2018_12546.exp2.{arm}.ditto_to_influx"
        ),
        "K": condition(
            f"capability.2018_12546.exp2.{arm}.cve_effect_carried_to_influx"
        ),
        "Y": condition(
            f"receiver.influxdb.2018_12546.exp2.{arm}.retained_processing"
        ),
    }


def target_channels(arm: str, target: str, experiment: str = "exp2") -> dict:
    prefix = f"target.2018_12546.{experiment}.{arm}.{target}"
    common_unknown = {
        "state": "U",
        "evidence_class": "EVIDENCE_GAP",
        "source": "No confidentiality or availability experiment",
        "evidence": [],
        "reason": (
            "The controlled experiment tested an integrity-policy "
            "consequence only; it does not establish C or A."
        ),
        "scope": "Experiment-specific observation window only.",
    }
    if target == "mosquitto":
        integrity = copy.deepcopy(common_unknown)
        integrity["reason"] = (
            "Retained delivery after revocation is broker behaviour, not a "
            "specific adverse integrity effect on Mosquitto itself."
        )
    elif arm == "vulnerable" and target in ("ditto", "influxdb"):
        integrity = {
            "state": "T",
            "evidence_class": "CONTROLLED_REPRODUCTION",
            "source": (
                "output/evidence_runs/"
                "cve-2018-12546-downstream-20261118T200923198752Z.json"
            ),
            "evidence": [
                (
                    "The retained command changed the isolated Ditto Thing "
                    "after publisher write revocation was independently enforced."
                    if target == "ditto"
                    else "The corresponding retained command produced accepted "
                    "InfluxDB writes carrying the retained marker."
                )
            ],
            "reason": (
                "An integrity-policy consequence is observed, but its "
                "numerical magnitude is unavailable."
            ),
            "scope": (
                "One temporary deployment, isolated Thing, writer and "
                "observation window."
            ),
        }
    else:
        integrity = {
            "state": "F",
            "evidence_class": "CONTROLLED_REPRODUCTION_CONTROL",
            "source": (
                "output/evidence_runs/"
                "cve-2018-12546-downstream-20261118T200923198752Z.json"
            ),
            "evidence": [
                (
                    "The isolated control Thing remained at its 37.0/BASELINE "
                    "state."
                    if target == "ditto"
                    else "No retained-marker database row was found in the "
                    "bounded control window."
                )
            ],
            "reason": (
                "No policy consequence was observed for this attempted "
                "retained command in the control window."
            ),
            "scope": (
                "One temporary deployment, isolated Thing, writer and "
                "observation window."
            ),
        }
    return {
        "C": {**copy.deepcopy(common_unknown), "proposition_id": f"{prefix}.C"},
        "I": {**copy.deepcopy(integrity), "proposition_id": f"{prefix}.I"},
        "A": {**copy.deepcopy(common_unknown), "proposition_id": f"{prefix}.A"},
    }


def deployment_record(
    *,
    deployment_id: str,
    component_id: str,
    display_name: str,
    version: str,
    arm_evidence: dict,
    artifact: str,
) -> dict:
    deployment = arm_evidence["deployment"]
    return {
        "deployment_id": deployment_id,
        "component_id": component_id,
        "display_name": display_name,
        "version": version,
        "discovery_evidence": {
            "source_artifact": artifact,
            "deployment_id": deployment_id,
            "container_id": deployment["container_id"],
            "image_reference": deployment["image_reference"],
            "image_id": deployment["image_id"],
            "runtime_version": deployment["runtime_version"],
            "docker_network": deployment["network"],
            "network_alias": deployment.get("network_alias"),
            "configuration": deployment["configuration"],
            "temporary_deployment": True,
        },
    }


def main() -> Path:
    required = (
        V7_PATH,
        EXPERIMENT_1_PATH,
        EXPERIMENT_2_PATH,
        READBACK_PATH,
        EBSR_PATH,
        ADAPTER_PATH,
    )
    for path in required:
        if not path.exists():
            raise FileNotFoundError(path)

    v7 = load_json(V7_PATH)
    experiment_1 = load_json(EXPERIMENT_1_PATH)
    experiment_2 = load_json(EXPERIMENT_2_PATH)
    readback = load_json(READBACK_PATH)

    if experiment_1.get("result") != "COMPLETED":
        raise ValueError("Experiment 1 is not complete.")
    if experiment_2.get("result") != "COMPLETED_READBACK_PENDING":
        raise ValueError("Experiment 2 is not the expected completed run.")
    if readback.get("status") != "CONFIRMED":
        raise ValueError("The InfluxDB readback verification is not confirmed.")
    if readback.get("result") != "PAIRED_DOWNSTREAM_DIFFERENCE_CONFIRMED":
        raise ValueError("The verified paired result is not supported.")

    vulnerable = experiment_2["arms"]["vulnerable"]
    control = experiment_2["arms"]["control"]
    vulnerable_readback = readback["vulnerable_retained_marker"]
    control_readback = readback["control_retained_marker"]
    control_support = readback["control_window_support"]

    if vulnerable_readback["row_count"] != 2:
        raise ValueError("Expected two vulnerable retained-marker rows.")
    if control_readback["row_count"] != 0:
        raise ValueError("Expected no control retained-marker rows.")
    if not vulnerable["retained"]["revocation"]["enforced"]:
        raise ValueError("Vulnerable publisher revocation was not enforced.")
    if not control["retained"]["revocation"]["enforced"]:
        raise ValueError("Control publisher revocation was not enforced.")
    if "check_retain_source true" not in control["deployment"]["configuration"]:
        raise ValueError("The control check_retain_source setting is missing.")

    source_assessment = v7["cve_assessments"][0]
    source_row = next(
        row
        for row in source_assessment["affected"]
        if row.get("cve_id") == CVE_ID
    )
    vector = source_row["cvss"]["primary"]["vector"]

    hashes = {
        "v7_scenario": file_hash(V7_PATH),
        "experiment_1": file_hash(EXPERIMENT_1_PATH),
        "experiment_2": file_hash(EXPERIMENT_2_PATH),
        "readback_verification": file_hash(READBACK_PATH),
        "vulnerable_csv": file_hash(
            Path(
                readback["source_csv_exports"]["vulnerable_retained"][
                    "project_copy"
                ]
            )
        ),
        "control_csv": file_hash(
            Path(
                readback["source_csv_exports"]["control_window"][
                    "project_copy"
                ]
            )
        ),
        "ebsr": file_hash(EBSR_PATH),
        "adapter": file_hash(ADAPTER_PATH),
    }

    deployments = [
        deployment_record(
            deployment_id=EXPERIMENT_1_VULNERABLE_ID,
            component_id="mosquitto",
            display_name="Experiment 1 vulnerable Mosquitto 1.5.5",
            version="1.5.5",
            arm_evidence=experiment_1["arms"]["vulnerable"],
            artifact=str(EXPERIMENT_1_PATH.relative_to(ROOT)).replace("\\", "/"),
        ),
        deployment_record(
            deployment_id=EXPERIMENT_1_CONTROL_ID,
            component_id="mosquitto",
            display_name="Experiment 1 control Mosquitto 2.1.2",
            version="2.1.2",
            arm_evidence=experiment_1["arms"]["control"],
            artifact=str(EXPERIMENT_1_PATH.relative_to(ROOT)).replace("\\", "/"),
        ),
        deployment_record(
            deployment_id=VULNERABLE_DEPLOYMENT_ID,
            component_id="mosquitto",
            display_name="Experiment 2 vulnerable Mosquitto 1.5.5",
            version="1.5.5",
            arm_evidence=vulnerable,
            artifact=str(EXPERIMENT_2_PATH.relative_to(ROOT)).replace("\\", "/"),
        ),
        deployment_record(
            deployment_id=CONTROL_DEPLOYMENT_ID,
            component_id="mosquitto",
            display_name="Experiment 2 control Mosquitto 2.1.2",
            version="2.1.2",
            arm_evidence=control,
            artifact=str(EXPERIMENT_2_PATH.relative_to(ROOT)).replace("\\", "/"),
        ),
        {
            "deployment_id": DITTO_DEPLOYMENT_ID,
            "component_id": "eclipse_ditto",
            "display_name": "Eclipse Ditto connectivity 3.9.7",
            "version": "3.9.7",
            "discovery_evidence": {
                "source_artifact": str(EXPERIMENT_2_PATH.relative_to(ROOT)),
                "container_name": "docker-connectivity-1",
                "image_reference": "eclipse/ditto-connectivity:3.9.7",
                "vulnerable_connection_id": vulnerable["retained"][
                    "downstream_observation"
                ]["event_connection"]["details"]["connectionId"],
                "control_connection_id": control["retained"][
                    "downstream_observation"
                ]["event_connection"]["details"]["connectionId"],
                "scope": "Existing Ditto service used by both isolated arms.",
            },
        },
        {
            "deployment_id": INFLUX_DEPLOYMENT_ID,
            "component_id": "influxdb",
            "display_name": "InfluxDB 2.7.11",
            "version": "2.7.11",
            "discovery_evidence": {
                "source_artifact": str(READBACK_PATH.relative_to(ROOT)),
                "bucket": "iomt-ditto-influx-test-cd1c965d2a",
                "organisation": "IoMT-Lab",
                "writer_event_observation": (
                    "The temporary Ditto event writer received matching "
                    "Thing events and InfluxDB returned HTTP 204."
                ),
                "readback_status": "CONFIRMED",
            },
        },
    ]

    attacker_profiles = [
        {
            "attacker_id": "ATTACKER-12546-EXP2-VULNERABLE",
            "description": (
                "Authenticated publisher in the temporary vulnerable arm with "
                "initial write permission, later revoked."
            ),
            "capabilities": [
                "Authenticate to the temporary broker.",
                "Publish a retained command while authorized.",
            ],
            "provenance": str(EXPERIMENT_2_PATH.relative_to(ROOT)),
        },
        {
            "attacker_id": "ATTACKER-12546-EXP2-CONTROL",
            "description": (
                "Authenticated publisher in the temporary control arm with "
                "initial write permission, later revoked."
            ),
            "capabilities": [
                "Authenticate to the temporary broker.",
                "Publish a retained command while authorized.",
            ],
            "provenance": str(EXPERIMENT_2_PATH.relative_to(ROOT)),
        },
    ]

    architecture_evidence = [
        {
            "relationship_id": (
                "relationship.2018_12546.exp2.vulnerable.mosquitto_to_ditto"
            ),
            "source_deployment_id": VULNERABLE_DEPLOYMENT_ID,
            "target_deployment_id": DITTO_DEPLOYMENT_ID,
            "transition_type": "DF",
            "status": "SUPPORTED",
            "evidence": [
                "The temporary Ditto connection was open on the isolated topic.",
                "The normal and post-control commands changed the isolated Thing.",
                "After verified publisher revocation, broker logs show retained "
                "PUBLISH delivery to Ditto and the Thing changed to the retained marker.",
            ],
            "notes": "Observed only in the temporary vulnerable experiment configuration.",
        },
        {
            "relationship_id": (
                "relationship.2018_12546.exp2.control.mosquitto_to_ditto"
            ),
            "source_deployment_id": CONTROL_DEPLOYMENT_ID,
            "target_deployment_id": DITTO_DEPLOYMENT_ID,
            "transition_type": "DF",
            "status": "SUPPORTED",
            "evidence": [
                "The temporary Ditto connection was open on the isolated topic.",
                "The normal and post-control commands changed the isolated Thing.",
                "No retained delivery to Ditto occurred after revocation.",
            ],
            "notes": (
                "The data-flow relationship is operational; the retained "
                "command is separately withheld by the control configuration."
            ),
        },
        {
            "relationship_id": (
                "relationship.2018_12546.exp2.vulnerable.ditto_to_influx"
            ),
            "source_deployment_id": DITTO_DEPLOYMENT_ID,
            "target_deployment_id": INFLUX_DEPLOYMENT_ID,
            "transition_type": "DF",
            "status": "SUPPORTED",
            "evidence": [
                "Normal and post-control Thing events produced HTTP 204 writes.",
                "The retained marker produced two matching InfluxDB rows.",
            ],
            "notes": "The CVE-free step keeps A and G UNKNOWN.",
        },
        {
            "relationship_id": (
                "relationship.2018_12546.exp2.control.ditto_to_influx"
            ),
            "source_deployment_id": DITTO_DEPLOYMENT_ID,
            "target_deployment_id": INFLUX_DEPLOYMENT_ID,
            "transition_type": "DF",
            "status": "SUPPORTED",
            "evidence": [
                "Normal and post-control Thing events produced HTTP 204 writes.",
                "No retained-marker row was found in the bounded control window.",
            ],
            "notes": (
                "The writer path is operational, but the retained-marker "
                "effect is absent."
            ),
        },
    ]

    evidence = [
        evidence_item(
            "cve.2018_12546.exp1.vulnerable.applicability",
            "T",
            "SAVED_NVD_CPE_AND_CONTROLLED_VERSION_EVIDENCE",
            str(V7_PATH.relative_to(ROOT)),
            [
                "The saved CPE decision is AFFECTED for Mosquitto 1.5.5.",
                "The Experiment 1 vulnerable broker reported runtime version 1.5.5.",
            ],
            None,
            scope="Experiment 1 temporary vulnerable deployment only.",
        ),
        evidence_item(
            "cve.2018_12546.exp1.control.applicability",
            "F",
            "SAVED_NVD_CPE_AND_CONTROLLED_VERSION_EVIDENCE",
            "mosquitto_2.1.2_baseline_results.json",
            [
                "The affected range ends at 1.5.5 inclusive.",
                "The Experiment 1 control broker reported runtime version 2.1.2.",
            ],
            "The CVE applicability proposition is FALSE for the Experiment 1 control deployment.",
            scope="Experiment 1 temporary control deployment only.",
        ),
        evidence_item(
            "attacker.2018_12546.exp1.vulnerable.authenticated_publisher",
            "T",
            "CONTROLLED_REPRODUCTION",
            str(EXPERIMENT_1_PATH.relative_to(ROOT)),
            [
                "Authentication was enabled and a wrong password was rejected.",
                "The publisher authenticated and retained publication was acknowledged.",
                "The publisher identity was distinct from the subscriber.",
            ],
            None,
            scope="Experiment 1 temporary vulnerable arm.",
        ),
        evidence_item(
            "attacker.2018_12546.exp1.control.authenticated_publisher",
            "T",
            "CONTROLLED_REPRODUCTION_CONTROL",
            str(EXPERIMENT_1_PATH.relative_to(ROOT)),
            [
                "Authentication was enabled and a wrong password was rejected.",
                "The publisher authenticated and retained publication was acknowledged.",
                "The publisher identity was distinct from the subscriber.",
            ],
            None,
            scope="Experiment 1 temporary control arm.",
        ),
        evidence_item(
            "preconditions.2018_12546.exp1.vulnerable.broker_configuration",
            "T",
            "CONTROLLED_REPRODUCTION",
            str(EXPERIMENT_1_PATH.relative_to(ROOT)),
            [
                experiment_1["arms"]["vulnerable"]["deployment"][
                    "configuration"
                ],
                "Publisher write permission was revoked and SIGHUP reload was observed.",
            ],
            None,
            scope="Experiment 1 vulnerable broker and observation window.",
        ),
        evidence_item(
            "preconditions.2018_12546.exp1.control.broker_configuration",
            "T",
            "CONTROLLED_REPRODUCTION_CONTROL",
            str(EXPERIMENT_1_PATH.relative_to(ROOT)),
            [
                experiment_1["arms"]["control"]["deployment"][
                    "configuration"
                ],
                "check_retain_source=true was explicit.",
                "Publisher write permission was revoked and SIGHUP reload was observed.",
            ],
            None,
            scope="Experiment 1 control broker and observation window.",
        ),
        evidence_item(
            "cve.2018_12546.exp2.vulnerable.applicability",
            "T",
            "SAVED_NVD_CPE_AND_CONTROLLED_VERSION_EVIDENCE",
            str(V7_PATH.relative_to(ROOT)),
            [
                "The saved CPE decision is AFFECTED for Mosquitto 1.5.5.",
                "The temporary vulnerable broker reported runtime version 1.5.5.",
            ],
            None,
            scope="Temporary vulnerable deployment only.",
        ),
        evidence_item(
            "cve.2018_12546.exp2.control.applicability",
            "F",
            "SAVED_NVD_CPE_AND_CONTROLLED_VERSION_EVIDENCE",
            "mosquitto_2.1.2_baseline_results.json",
            [
                "The affected range ends at 1.5.5 inclusive.",
                "The temporary control broker reported runtime version 2.1.2.",
                "The saved control baseline records zero affected candidates.",
            ],
            "The CVE applicability proposition is FALSE for the temporary control deployment.",
            scope="Temporary control deployment only.",
        ),
        evidence_item(
            "attacker.2018_12546.exp2.vulnerable.authenticated_publisher",
            "T",
            "CONTROLLED_REPRODUCTION",
            str(EXPERIMENT_2_PATH.relative_to(ROOT)),
            [
                "Authentication was enabled and a wrong password was rejected.",
                "The experiment publisher authenticated and initially published the retained command.",
                "Publisher write permission was subsequently revoked and enforcement was verified.",
            ],
            None,
            scope="Temporary vulnerable arm.",
        ),
        evidence_item(
            "attacker.2018_12546.exp2.control.authenticated_publisher",
            "T",
            "CONTROLLED_REPRODUCTION_CONTROL",
            str(EXPERIMENT_2_PATH.relative_to(ROOT)),
            [
                "Authentication was enabled and a wrong password was rejected.",
                "The experiment publisher authenticated and initially published the retained command.",
                "Publisher write permission was subsequently revoked and enforcement was verified.",
            ],
            None,
            scope="Temporary control arm.",
        ),
        evidence_item(
            "preconditions.2018_12546.exp2.vulnerable.broker_configuration",
            "T",
            "CONTROLLED_REPRODUCTION",
            str(EXPERIMENT_2_PATH.relative_to(ROOT)),
            [
                vulnerable["deployment"]["configuration"],
                "Retained command was stored and delivered after an enforced ACL reload.",
            ],
            None,
            scope="Temporary vulnerable broker and isolated MQTT 3.1.1 test.",
        ),
        evidence_item(
            "preconditions.2018_12546.exp2.control.broker_configuration",
            "T",
            "CONTROLLED_REPRODUCTION_CONTROL",
            str(EXPERIMENT_2_PATH.relative_to(ROOT)),
            [
                control["deployment"]["configuration"],
                "check_retain_source=true was explicit.",
                "Retained command was stored while authorized; after revocation it was withheld.",
            ],
            None,
            scope="Temporary control broker and isolated MQTT 3.1.1 test.",
        ),
        evidence_item(
            "architecture.2018_12546.exp2.vulnerable.mosquitto_to_ditto",
            "T",
            "CONTROLLED_REPRODUCTION",
            str(EXPERIMENT_2_PATH.relative_to(ROOT)),
            [
                "Ditto consumed the retained command after revocation.",
                "The retained marker changed the isolated vulnerable Thing.",
            ],
            None,
            scope="Temporary vulnerable experiment window.",
        ),
        evidence_item(
            "architecture.2018_12546.exp2.control.mosquitto_to_ditto",
            "T",
            "CONTROLLED_REPRODUCTION_CONTROL",
            str(EXPERIMENT_2_PATH.relative_to(ROOT)),
            [
                "Ditto processed normal and post-control messages on the same link.",
                "The retained command was not delivered by the control broker.",
            ],
            None,
            scope="Temporary control experiment window.",
        ),
        evidence_item(
            "architecture.2018_12546.exp1.vulnerable.direct",
            "T",
            "CONTROLLED_REPRODUCTION",
            str(EXPERIMENT_1_PATH.relative_to(ROOT)),
            [
                "Exact temporary deployment and run were time-scoped.",
                "A fresh authorized subscriber received the old retained marker after revocation.",
            ],
            None,
            scope="Experiment 1 vulnerable observation window.",
        ),
        evidence_item(
            "architecture.2018_12546.exp1.control.direct",
            "T",
            "CONTROLLED_REPRODUCTION_CONTROL",
            str(EXPERIMENT_1_PATH.relative_to(ROOT)),
            [
                "Exact temporary deployment and run were time-scoped.",
                "The matching control withheld the retained marker.",
            ],
            None,
            scope="Experiment 1 control observation window.",
        ),
        evidence_item(
            "capability.2018_12546.exp1.vulnerable.retained_command",
            "T",
            "CONTROLLED_REPRODUCTION",
            str(EXPERIMENT_1_PATH.relative_to(ROOT)),
            [
                "After verified revocation, a fresh authorized subscriber received the old retained marker."
            ],
            None,
            scope="Experiment 1 direct retained-message transition.",
        ),
        evidence_item(
            "capability.2018_12546.exp1.control.retained_command",
            "F",
            "CONTROLLED_REPRODUCTION_CONTROL",
            str(EXPERIMENT_1_PATH.relative_to(ROOT)),
            [
                "After verified revocation, the check_retain_source=true control withheld the old retained marker."
            ],
            "The control blocked the retained-message transition.",
            scope="Experiment 1 direct control transition.",
        ),
        evidence_item(
            "receiver.mosquitto.2018_12546.exp1.vulnerable.retained_delivery",
            "T",
            "CONTROLLED_REPRODUCTION",
            str(EXPERIMENT_1_PATH.relative_to(ROOT)),
            [
                "A fresh authorized subscriber received the retained marker with retained flag set."
            ],
            None,
            scope="Experiment 1 vulnerable subscriber observation.",
        ),
        evidence_item(
            "receiver.mosquitto.2018_12546.exp1.control.retained_delivery",
            "F",
            "CONTROLLED_REPRODUCTION_CONTROL",
            str(EXPERIMENT_1_PATH.relative_to(ROOT)),
            [
                "A fresh authorized subscriber received no retained marker in the bounded control window."
            ],
            "The control prevented retained delivery.",
            scope="Experiment 1 control subscriber observation.",
        ),
        evidence_item(
            "capability.2018_12546.exp2.vulnerable.retained_command",
            "T",
            "CONTROLLED_REPRODUCTION",
            str(EXPERIMENT_1_PATH.relative_to(ROOT)),
            [
                "After verified revocation, Experiment 1 delivered the old retained marker to a fresh subscriber.",
                "Experiment 2 again delivered the retained marker to Ditto.",
            ],
            None,
            scope="Exact retained command and revocation transition.",
        ),
        evidence_item(
            "capability.2018_12546.exp2.control.retained_command",
            "F",
            "CONTROLLED_REPRODUCTION_CONTROL",
            str(EXPERIMENT_1_PATH.relative_to(ROOT)),
            [
                "Experiment 1's check_retain_source=true control withheld the marker.",
                "Experiment 2's explicit check_retain_source=true control delivered no retained command to Ditto.",
            ],
            "No retained delivery occurred in the control configuration.",
            scope="Exact control transition.",
        ),
        evidence_item(
            "receiver.ditto.2018_12546.exp2.vulnerable.retained_processing",
            "T",
            "CONTROLLED_REPRODUCTION",
            str(EXPERIMENT_2_PATH.relative_to(ROOT)),
            [
                "The isolated Thing changed to temperature 42.75 and the retained marker.",
                "The associated Ditto event reached the temporary writer.",
            ],
            None,
            scope="Temporary vulnerable Ditto Thing and receiver window.",
        ),
        evidence_item(
            "receiver.ditto.2018_12546.exp2.control.retained_processing",
            "F",
            "CONTROLLED_REPRODUCTION_CONTROL",
            str(EXPERIMENT_2_PATH.relative_to(ROOT)),
            [
                "The isolated Thing remained at 37.0/BASELINE after the retained stage.",
                "No retained-marker writer event was observed.",
            ],
            "The retained command was not processed by the control receiver.",
            scope="Temporary control Ditto Thing and receiver window.",
        ),
        evidence_item(
            "unresolved.2018_12546.cve_free_step.A",
            "U",
            "MODEL_SEMANTICS_GAP",
            str(V7_PATH.relative_to(ROOT)),
            [
                "The frozen material defines no independent A meaning for a cve_ids: [] step."
            ],
            "A remains UNKNOWN and does not inherit the relationship result.",
            scope="CVE-free ordered transition.",
        ),
        evidence_item(
            "unresolved.2018_12546.cve_free_step.G",
            "U",
            "MODEL_SEMANTICS_GAP",
            str(V7_PATH.relative_to(ROOT)),
            [
                "The frozen material defines no independent G meaning for a cve_ids: [] step."
            ],
            "G remains UNKNOWN and does not inherit the relationship result.",
            scope="CVE-free ordered transition.",
        ),
        evidence_item(
            "preconditions.2018_12546.exp2.vulnerable.ditto_to_influx_write",
            "T",
            "CONTROLLED_REPRODUCTION",
            str(READBACK_PATH.relative_to(ROOT)),
            [
                "The writer was ready, the event connection was open, and InfluxDB health was 200.",
                "Normal, retained and post-control events produced HTTP 204 writes.",
            ],
            None,
            scope="Temporary vulnerable writer and bucket.",
        ),
        evidence_item(
            "preconditions.2018_12546.exp2.control.ditto_to_influx_write",
            "T",
            "CONTROLLED_REPRODUCTION_CONTROL",
            str(READBACK_PATH.relative_to(ROOT)),
            [
                "The same writer and bucket configuration was used.",
                "Normal and post-control events produced confirmed database rows.",
            ],
            None,
            scope="Temporary control writer and bucket.",
        ),
        evidence_item(
            "architecture.2018_12546.exp2.vulnerable.ditto_to_influx",
            "T",
            "CONTROLLED_REPRODUCTION",
            str(READBACK_PATH.relative_to(ROOT)),
            [
                "Two matching retained-marker rows have distinct timestamps.",
                "Rows match the exact Thing ID, marker and value 42.75.",
            ],
            None,
            scope="CVE-free data-flow step in the temporary vulnerable arm.",
        ),
        evidence_item(
            "architecture.2018_12546.exp2.control.ditto_to_influx",
            "T",
            "CONTROLLED_REPRODUCTION_CONTROL",
            str(READBACK_PATH.relative_to(ROOT)),
            [
                "Normal and post-control rows confirm the writer path.",
                "The retained-marker query returned zero rows in the bounded window.",
            ],
            None,
            scope="CVE-free data-flow step in the temporary control arm.",
        ),
        evidence_item(
            "capability.2018_12546.exp2.vulnerable.cve_effect_carried_to_influx",
            "T",
            "CONTROLLED_REPRODUCTION",
            str(READBACK_PATH.relative_to(ROOT)),
            [
                "The retained marker from the CVE path reached the accepted InfluxDB write stage."
            ],
            None,
            scope="Retained command chain in the temporary vulnerable arm.",
        ),
        evidence_item(
            "capability.2018_12546.exp2.control.cve_effect_carried_to_influx",
            "F",
            "CONTROLLED_REPRODUCTION_CONTROL",
            str(READBACK_PATH.relative_to(ROOT)),
            [
                "No retained-marker row or writer event exists for the control arm."
            ],
            "The CVE-specific retained effect did not reach InfluxDB.",
            scope="Retained command chain in the temporary control arm.",
        ),
        evidence_item(
            "receiver.influxdb.2018_12546.exp2.vulnerable.retained_processing",
            "T",
            "CONTROLLED_REPRODUCTION",
            str(READBACK_PATH.relative_to(ROOT)),
            [
                "The vulnerable retained-marker CSV contains two rows.",
                "Both rows match the Thing ID, marker and temperature exactly.",
            ],
            None,
            scope="Temporary vulnerable InfluxDB write and readback.",
        ),
        evidence_item(
            "receiver.influxdb.2018_12546.exp2.control.retained_processing",
            "F",
            "CONTROLLED_REPRODUCTION_CONTROL",
            str(READBACK_PATH.relative_to(ROOT)),
            [
                "The control retained-marker query contains zero rows.",
                "Normal and post-control rows prove the writer itself remained operational.",
            ],
            "The retained command was not processed into the control telemetry record.",
            scope="Temporary control InfluxDB write and readback.",
        ),
        evidence_item(
            "observation.end_to_end.normal_telemetry_chain.exp2",
            "T",
            "CONTROLLED_REPRODUCTION_PREREQUISITE",
            str(EXPERIMENT_2_PATH.relative_to(ROOT)),
            [
                "Both arms delivered normal non-retained commands through "
                "Ditto to the isolated Thing.",
                "Normal events reached the writer with HTTP 204.",
                "The control normal and post-control rows were confirmed in InfluxDB.",
            ],
            None,
            scope="Temporary experiment configurations only.",
        ),
    ]

    target_evidence = []
    for arm, targets in (
        ("vulnerable", ("mosquitto", "ditto", "influxdb")),
        ("control", ("mosquitto", "ditto", "influxdb")),
    ):
        for target in targets:
            experiment = "exp1" if target == "mosquitto" else "exp2"
            for channel, value in target_channels(
                arm,
                target,
                experiment=experiment,
            ).items():
                proposition_id = value.pop("proposition_id")
                target_evidence.append({
                    "proposition_id": proposition_id,
                    "status": value.pop("state"),
                    **value,
                })
    evidence.extend(target_evidence)

    vulnerable_assessment = {
        "component": "Mosquitto",
        "component_id": "mosquitto",
        "deployment_id": VULNERABLE_DEPLOYMENT_ID,
        "display_name": "Experiment 2 vulnerable Mosquitto 1.5.5",
        "version": "1.5.5",
        "detected_version": "1.5.5",
        "assessment_version_source": (
            "The saved CVE-2018-12546 applicability is bound to the temporary "
            "Experiment 2 runtime version. No fresh NVD retrieval occurred."
        ),
        "discovery_evidence": deployments[2]["discovery_evidence"],
        "retrieval": copy.deepcopy(source_assessment["retrieval"]),
        "retrieval_source": "saved CVE-2018-12546 applicability snapshot",
        "affected": [copy.deepcopy(source_row)],
        "affected_other_scale": [],
        "unknown": [],
        "not_affected": [],
    }
    control_row = {
        "cve_id": CVE_ID,
        "status": "NOT_AFFECTED",
        "reason": (
            "The temporary control deployment reports Mosquitto 2.1.2, "
            "outside the affected range 1.0 through 1.5.5 inclusive."
        ),
        "cvss": copy.deepcopy(source_row.get("cvss")),
        "description": source_row.get("description"),
        "applicability": {
            "cve_id": CVE_ID,
            "version": "2.1.2",
            "status": "NOT_AFFECTED",
            "reason": (
                "Version 2.1.2 is above the saved affected boundary."
            ),
            "source_snapshot": "mosquitto_2.1.2_baseline_results.json",
        },
    }
    control_assessment = {
        "component": "Mosquitto",
        "component_id": "mosquitto",
        "deployment_id": CONTROL_DEPLOYMENT_ID,
        "display_name": "Experiment 2 control Mosquitto 2.1.2",
        "version": "2.1.2",
        "detected_version": "2.1.2",
        "assessment_version_source": (
            "The temporary Experiment 2 runtime version is checked against "
            "the saved affected boundary. No fresh NVD retrieval occurred."
        ),
        "discovery_evidence": deployments[3]["discovery_evidence"],
        "retrieval": {
            "status": "COMPLETE",
            "received": 35,
            "total_results": 35,
            "error": None,
        },
        "retrieval_source": "mosquitto_2.1.2_baseline_results.json",
        "affected": [],
        "affected_other_scale": [],
        "unknown": [],
        "not_affected": [control_row],
    }

    experiment_1_vulnerable_assessment = copy.deepcopy(
        vulnerable_assessment
    )
    experiment_1_vulnerable_assessment.update({
        "deployment_id": EXPERIMENT_1_VULNERABLE_ID,
        "display_name": "Experiment 1 vulnerable Mosquitto 1.5.5",
        "discovery_evidence": deployments[0]["discovery_evidence"],
        "assessment_version_source": (
            "The saved CVE-2018-12546 applicability is bound to the "
            "Experiment 1 runtime version and evidence window."
        ),
    })
    experiment_1_control_assessment = copy.deepcopy(
        control_assessment
    )
    experiment_1_control_assessment.update({
        "deployment_id": EXPERIMENT_1_CONTROL_ID,
        "display_name": "Experiment 1 control Mosquitto 2.1.2",
        "discovery_evidence": deployments[1]["discovery_evidence"],
        "assessment_version_source": (
            "The saved control applicability is bound to the Experiment 1 "
            "runtime version and evidence window."
        ),
    })

    scenarios = []
    for arm, deployment_id, attacker_id, reproduction_grade in (
        (
            "vulnerable",
            VULNERABLE_DEPLOYMENT_ID,
            "ATTACKER-12546-EXP2-VULNERABLE",
            "INDEPENDENTLY_REPRODUCED",
        ),
        (
            "control",
            CONTROL_DEPLOYMENT_ID,
            "ATTACKER-12546-EXP2-CONTROL",
            "REPRODUCTION_FAILED",
        ),
    ):
        first_cve_ids = [CVE_ID] if arm == "vulnerable" else []
        first_repro = (
            {CVE_ID: reproduction_grade}
            if arm == "vulnerable"
            else {}
        )
        direct_deployment_id = (
            EXPERIMENT_1_VULNERABLE_ID
            if arm == "vulnerable"
            else EXPERIMENT_1_CONTROL_ID
        )

        scenarios.append(
            {
                "scenario_id": f"EXP1-12546-{arm.upper()}-MOSQUITTO",
                "attacker_id": attacker_id,
                "target_deployment_id": direct_deployment_id,
                "cve_under_test": CVE_ID,
                "description": (
                    f"Experiment-scoped direct retained-message path for the "
                    f"{arm} temporary Mosquitto deployment."
                ),
                "paths": [
                    {
                        "path_id": f"exp1-12546-{arm}-direct",
                        "target_deployment_id": direct_deployment_id,
                        "target_channels": target_channels(
                            arm,
                            "mosquitto",
                            experiment="exp1",
                        ),
                        "transitions": [
                            {
                                "step_id": f"exp1-12546-{arm}-direct-step",
                                "source_deployment_id": direct_deployment_id,
                                "target_deployment_id": direct_deployment_id,
                                "transition_type": "DIRECT",
                                "cve_ids": first_cve_ids,
                                "reproduction_grades": first_repro,
                                "conditions": direct_conditions(arm),
                            }
                        ],
                    }
                ],
            }
        )

        scenarios.append(
            {
                "scenario_id": f"EXP2-12546-{arm.upper()}-DITTO",
                "attacker_id": attacker_id,
                "target_deployment_id": DITTO_DEPLOYMENT_ID,
                "cve_under_test": CVE_ID,
                "description": (
                    f"Experiment-scoped Mosquitto-to-Ditto retained-command "
                    f"path for the {arm} arm."
                ),
                "paths": [
                    {
                        "path_id": f"exp2-12546-{arm}-to-ditto",
                        "target_deployment_id": DITTO_DEPLOYMENT_ID,
                        "target_channels": target_channels(arm, "ditto"),
                        "transitions": [
                            {
                                "step_id": f"exp2-12546-{arm}-mqtt-to-ditto",
                                "source_deployment_id": deployment_id,
                                "target_deployment_id": DITTO_DEPLOYMENT_ID,
                                "transition_type": "DF",
                                "relationship_id": (
                                    f"relationship.2018_12546.exp2."
                                    f"{arm}.mosquitto_to_ditto"
                                ),
                                "cve_ids": first_cve_ids,
                                "reproduction_grades": first_repro,
                                "conditions": scenario_conditions(
                                    arm=arm,
                                    first_step="mosquitto_to_ditto",
                                ),
                            }
                        ],
                    }
                ],
            }
        )

        scenarios.append(
            {
                "scenario_id": f"EXP2-12546-{arm.upper()}-INFLUX",
                "attacker_id": attacker_id,
                "target_deployment_id": INFLUX_DEPLOYMENT_ID,
                "cve_under_test": CVE_ID,
                "description": (
                    f"Experiment-scoped retained-command chain through Ditto "
                    f"to InfluxDB for the {arm} arm."
                ),
                "paths": [
                    {
                        "path_id": f"exp2-12546-{arm}-to-influx",
                        "target_deployment_id": INFLUX_DEPLOYMENT_ID,
                        "target_channels": target_channels(arm, "influxdb"),
                        "transitions": [
                            {
                                "step_id": f"exp2-12546-{arm}-mqtt-to-ditto",
                                "source_deployment_id": deployment_id,
                                "target_deployment_id": DITTO_DEPLOYMENT_ID,
                                "transition_type": "DF",
                                "relationship_id": (
                                    f"relationship.2018_12546.exp2."
                                    f"{arm}.mosquitto_to_ditto"
                                ),
                                "cve_ids": first_cve_ids,
                                "reproduction_grades": first_repro,
                                "conditions": scenario_conditions(
                                    arm=arm,
                                    first_step="mosquitto_to_ditto",
                                ),
                            },
                            {
                                "step_id": f"exp2-12546-{arm}-ditto-to-influx",
                                "source_deployment_id": DITTO_DEPLOYMENT_ID,
                                "target_deployment_id": INFLUX_DEPLOYMENT_ID,
                                "transition_type": "DF",
                                "relationship_id": (
                                    f"relationship.2018_12546.exp2."
                                    f"{arm}.ditto_to_influx"
                                ),
                                "cve_ids": [],
                                "conditions": cve_free_conditions(arm),
                            },
                        ],
                    }
                ],
            }
        )

    validation_records = [
        {
            "validation_record_id": "EXP2-12546-VULNERABLE-REPRODUCTION",
            "deployment_id": VULNERABLE_DEPLOYMENT_ID,
            "cve_id": CVE_ID,
            "reproduction_grade": "INDEPENDENTLY_REPRODUCED",
            "independently_reproduced": True,
            "observation_window_utc": {
                "start": experiment_2["started_utc"],
                "stop": experiment_2["finished_utc"],
            },
            "broker_configuration": vulnerable["deployment"]["configuration"],
            "evidence": [
                str(EXPERIMENT_1_PATH.relative_to(ROOT)),
                str(EXPERIMENT_2_PATH.relative_to(ROOT)),
                str(READBACK_PATH.relative_to(ROOT)),
            ],
            "result": vulnerable["assessment"]["outcome"],
            "scope": "Temporary vulnerable Lab experiment only.",
        },
        {
            "validation_record_id": "EXP2-12546-CONTROL-REPRODUCTION",
            "deployment_id": CONTROL_DEPLOYMENT_ID,
            "cve_id": CVE_ID,
            "reproduction_grade": "REPRODUCTION_FAILED",
            "independently_reproduced": False,
            "observation_window_utc": {
                "start": experiment_2["started_utc"],
                "stop": experiment_2["finished_utc"],
            },
            "broker_configuration": control["deployment"]["configuration"],
            "evidence": [
                str(EXPERIMENT_1_PATH.relative_to(ROOT)),
                str(EXPERIMENT_2_PATH.relative_to(ROOT)),
                str(READBACK_PATH.relative_to(ROOT)),
            ],
            "result": control["assessment"]["outcome"],
            "scope": (
                "Intentional control; the vulnerable retained-delivery "
                "behaviour was not reproduced with check_retain_source=true."
            ),
        },
    ]

    document = {
        "schema_version": "1.1",
        "assessment_version": "research-cve-2018-12546-experiment-v8",
        "assessment_scope": (
            "Experiment-scoped Mosquitto 1.5.5 versus Mosquitto 2.1.2 "
            "retained-message path through Eclipse Ditto and InfluxDB."
        ),
        "derived_from": {
            "schema_reference": str(V7_PATH.relative_to(ROOT)),
            "v7_preserved": True,
            "frozen_mathematics_changed": False,
            "purpose": "Add controlled experiment evidence without replacing v7.",
        },
        "source_hashes": hashes,
        "evidence_provenance": {
            "experiment_1": str(EXPERIMENT_1_PATH.relative_to(ROOT)),
            "experiment_2": str(EXPERIMENT_2_PATH.relative_to(ROOT)),
            "readback_verification": str(READBACK_PATH.relative_to(ROOT)),
            "vulnerable_csv_copy": readback["source_csv_exports"][
                "vulnerable_retained"
            ]["project_copy"],
            "control_csv_copy": readback["source_csv_exports"][
                "control_window"
            ]["project_copy"],
            "frozen_evaluator": str(EBSR_PATH.relative_to(ROOT)),
            "adapter": str(ADAPTER_PATH.relative_to(ROOT)),
        },
        "condition_semantics": {
            "A": (
                "CVE applicability for a CVE-carrying transition; for the "
                "control arm A is bound to its explicit NOT_AFFECTED control "
                "applicability proposition."
            ),
            "G": (
                "Observed actor prerequisite: an authenticated publisher "
                "with initial write permission before revocation."
            ),
            "H": (
                "Experiment-specific deployment and configuration prerequisites."
            ),
            "B": (
                "Explicit, deployment-bound DF/relationship observation during "
                "the experiment window."
            ),
            "K": (
                "CVE-specific capability carried through the tested transition."
            ),
            "Y": (
                "Receiver processing and receiver-control outcome for the "
                "same tested command."
            ),
            "target_C_I_A": (
                "Experiment-specific target consequences only; source CVSS "
                "weights are never copied."
            ),
            "cve_free_A_G": (
                "For cve_ids: [], frozen model semantics remain undefined; A "
                "and G stay UNKNOWN."
            ),
        },
        "experiment_governance": {
            "live_experiment_rerun": False,
            "baseline_transfer_allowed": False,
            "historical_manual_grade_upgraded": False,
            "control_check_retain_source": True,
            "experiment_1_vulnerable_configuration": experiment_1["arms"][
                "vulnerable"
            ]["deployment"]["configuration"],
            "experiment_1_controls": experiment_1["arms"]["control"][
                "deployment"
            ]["configuration"],
            "experiment_2_vulnerable_configuration": vulnerable["deployment"][
                "configuration"
            ],
            "experiment_2_control_configuration": control["deployment"][
                "configuration"
            ],
        },
        "research_decisions": [
            {
                "decision_id": "CVE_FREE_STEP_A_G_UNCHANGED",
                "status": "APPLIED",
                "decision": (
                    "A and G remain UNKNOWN on every cve_ids: [] Ditto-to-"
                    "InfluxDB step and do not inherit B, H, K or Y."
                ),
                "citations": [str(V7_PATH.relative_to(ROOT))],
            },
            {
                "decision_id": "CONTROL_APPLICABILITY_SEPARATE",
                "status": "APPLIED",
                "decision": (
                    "The 2.1.2 control is NOT_AFFECTED for CVE-2018-12546 "
                    "and its control scenarios use an explicit FALSE A "
                    "proposition, not an inferred vulnerable path."
                ),
                "citations": ["mosquitto_2.1.2_baseline_results.json"],
            },
            {
                "decision_id": "DOWNSTREAM_INTEGRITY_CONSEQUENCE_NO_MAGNITUDE",
                "status": "APPLIED",
                "decision": (
                    "The vulnerable Ditto and InfluxDB integrity-policy "
                    "consequences are TRUE with numerical magnitude "
                    "UNQUANTIFIED. C and A remain UNKNOWN."
                ),
                "citations": [
                    str(EXPERIMENT_2_PATH.relative_to(ROOT)),
                    str(READBACK_PATH.relative_to(ROOT)),
                ],
            },
            {
                "decision_id": "DUPLICATE_ROWS_DIRECTLY_OBSERVED",
                "status": "RECORDED",
                "decision": (
                    "Two matching vulnerable retained-marker rows with "
                    "distinct timestamps are recorded. The CSV establishes "
                    "the row count; no duplication cause is claimed."
                ),
                "citations": [
                    readback["source_csv_exports"]["vulnerable_retained"][
                        "project_copy"
                    ]
                ],
            },
            {
                "decision_id": "NO_BASELINE_TRANSFER",
                "status": "APPLIED",
                "decision": (
                    "Experiment results apply only to the named temporary "
                    "deployments and windows, not restored baseline deployments."
                ),
                "citations": [
                    str(EXPERIMENT_2_PATH.relative_to(ROOT)),
                    str(READBACK_PATH.relative_to(ROOT)),
                ],
            },
            {
                "decision_id": "HISTORICAL_MANUAL_SEPARATE",
                "status": "PRESERVED",
                "decision": (
                    "The historical CVE-2018-12546 observation remains "
                    "MANUALLY_OBSERVED in v7. The v8 scenario uses a separate "
                    "controlled reproduction record."
                ),
                "citations": [str(V7_PATH.relative_to(ROOT))],
            },
        ],
        "deployments": deployments,
        "attacker_profiles": attacker_profiles,
        "architecture_evidence": architecture_evidence,
        "evidence": evidence,
        "cve_assessments": [
            experiment_1_vulnerable_assessment,
            experiment_1_control_assessment,
            vulnerable_assessment,
            control_assessment,
        ],
        "scenarios": scenarios,
        "validation_records": validation_records,
        "observations": [
            {
                "observation_id": experiment_1["run_id"],
                "evidence_class": "CONTROLLED_REPRODUCTION_EXPERIMENT_1",
                "deployments": {
                    "vulnerable": EXPERIMENT_1_VULNERABLE_ID,
                    "control": EXPERIMENT_1_CONTROL_ID,
                },
                "window_utc": {
                    "start": experiment_1["run_started_utc"],
                    "stop": experiment_1["run_finished_utc"],
                },
                "result": experiment_1["comparison"],
                "limitations": experiment_1["limitations"],
            },
            {
                "observation_id": experiment_2["run_id"],
                "evidence_class": "CONTROLLED_REPRODUCTION_EXPERIMENT_2",
                "deployments": {
                    "vulnerable": VULNERABLE_DEPLOYMENT_ID,
                    "control": CONTROL_DEPLOYMENT_ID,
                    "ditto": DITTO_DEPLOYMENT_ID,
                    "influxdb": INFLUX_DEPLOYMENT_ID,
                },
                "window_utc": {
                    "start": experiment_2["started_utc"],
                    "stop": experiment_2["finished_utc"],
                },
                "result": experiment_2["comparison"],
                "vulnerable_thing_id": vulnerable["thing_id"],
                "control_thing_id": control["thing_id"],
                "vulnerable_retained_rows": vulnerable_readback["rows"],
                "control_retained_row_count": control_readback["row_count"],
                "control_support_rows": control_support["rows"],
                "scope_limit": (
                    "Integrity-policy consequences in temporary deployments; "
                    "numerical magnitudes remain UNQUANTIFIED."
                ),
            },
        ],
        "readback_verification": {
            "record": str(READBACK_PATH.relative_to(ROOT)),
            "status": readback["status"],
            "result": readback["result"],
            "evidence_unchanged": readback["source_evidence"]["unchanged"],
            "vulnerable_row_count": vulnerable_readback["row_count"],
            "control_row_count": control_readback["row_count"],
            "duplicate_rows": vulnerable_readback[
                "database_duplicate_rows_confirmed"
            ],
            "duplicate_cause": "UNKNOWN",
        },
        "experiment_reproduction_scope": {
            "vulnerable": {
                "source_observation": "INDEPENDENTLY_REPRODUCED",
                "downstream_cve_specific_observation": (
                    "DITTO_AND_INFLUXDB_POLICY_EFFECT_OBSERVED"
                ),
                "normal_path": "VERIFIED_IN_BOTH_ARMS",
                "target_magnitude": "UNQUANTIFIED",
            },
            "control": {
                "source_observation": "CONTROL_BEHAVIOUR_OBSERVED",
                "downstream_cve_specific_observation": "NO_RETAINED_EFFECT",
                "normal_path": "VERIFIED_IN_BOTH_ARMS",
                "target_magnitude": "NOT_APPLICABLE_TO_OBSERVED_EVENT",
            },
            "baseline_transfer": "NOT_PERFORMED",
            "historical_manual_record": "PRESERVED_SEPARATELY",
        },
    }

    v7_hash_before = hashes["v7_scenario"]
    ebsr_hash_before = hashes["ebsr"]
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    if file_hash(V7_PATH) != v7_hash_before:
        raise RuntimeError("The frozen v7 scenario changed unexpectedly.")
    if file_hash(EBSR_PATH) != ebsr_hash_before:
        raise RuntimeError("The frozen EBSR evaluator changed unexpectedly.")

    return OUTPUT_PATH


if __name__ == "__main__":
    print(main())
