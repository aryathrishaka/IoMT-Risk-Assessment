"""Build v7 with one direct CVE-2018-12550 scenario from v6."""

from __future__ import annotations

import copy
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
V6_PATH = ROOT / "scenarios" / "ebsr_mosquitto_12546_12551_v6.json"
OUTPUT_PATH = ROOT / "scenarios" / "ebsr_mosquitto_12546_12550_12551_v7.json"
ACL_OBSERVATION = (
    ROOT
    / "output"
    / "evidence_runs"
    / "mosquitto_acl_loaded_state_20261116T192251865Z.json"
)
SAVED_37_CVE_ASSESSMENT = (
    ROOT
    / "output"
    / "ebsr_assessments"
    / "ebsr-assessment-20261110T140855977011Z-v1.0.json"
)


def main() -> Path:
    if not V6_PATH.exists():
        raise FileNotFoundError(V6_PATH)
    if not ACL_OBSERVATION.exists():
        raise FileNotFoundError(ACL_OBSERVATION)
    if not SAVED_37_CVE_ASSESSMENT.exists():
        raise FileNotFoundError(SAVED_37_CVE_ASSESSMENT)

    observation = json.loads(
        ACL_OBSERVATION.read_text(encoding="utf-8-sig")
    )
    if observation["deployment"]["name"] != "mosquitto-vuln-lab":
        raise ValueError("ACL observation deployment does not match.")
    if observation["deployment"]["runtime_version"] != "1.5.5":
        raise ValueError("ACL observation version does not match.")
    if observation["listener"]["configured"] != "listener 1883":
        raise ValueError("ACL observation listener does not match.")
    if observation["configuration"]["acl_file"] != (
        "/mosquitto/config/aclfile"
    ):
        raise ValueError("ACL observation configuration does not match.")
    if observation["finding"]["empty_or_comment_only_acl"] != "FALSE":
        raise ValueError("ACL observation does not rule out the trigger.")
    if not observation["observation_window_utc"][
        "config_and_acl_unchanged"
    ]:
        raise ValueError("Configuration changed during the observation window.")

    document = copy.deepcopy(
        json.loads(V6_PATH.read_text(encoding="utf-8-sig"))
    )
    document["assessment_version"] = (
        "research-mosquitto-2026-11-10-v7"
    )
    document["derived_from"] = {
        "assessment_version": "research-mosquitto-2026-11-10-v6",
        "path": "scenarios/ebsr_mosquitto_12546_12551_v6.json",
        "purpose": "Add direct CVE-2018-12550 configuration-gated scenario",
        "frozen_mathematics_changed": False,
    }
    document["assessment_scope"] = (
        "Mosquitto, Eclipse Ditto and InfluxDB; CVE-2018-12546, "
        "CVE-2018-12550 and CVE-2018-12551"
    )
    document.setdefault("evidence_provenance", {}).setdefault(
        "runtime_and_architecture_sources", []
    ).append(
        str(ACL_OBSERVATION.relative_to(ROOT)).replace("\\", "/")
    )

    document.setdefault("attacker_profiles", []).append(
        {
            "attacker_id": "ATTACKER-12550-CLIENT-ACCESS-U",
            "description": (
                "A client capable of producing the CVE-2018-12550 empty-ACL "
                "condition in this deployment."
            ),
            "capabilities": [],
            "provenance": (
                "No deployment-specific actor or trigger validation exists; "
                "access remains UNKNOWN."
            ),
        }
    )

    document.setdefault("evidence", []).extend(
        [
            {
                "proposition_id": "cve.2018_12550.applicability",
                "status": "T",
                "evidence_class": "SAVED_NVD_CPE_ASSESSMENT",
                "source": (
                    "output/ebsr_assessments/"
                    "ebsr-assessment-20261110T140855977011Z-v1.0.json"
                ),
                "evidence": [
                    (
                        "Mosquitto 1.5.5 satisfies the affected NVD CPE "
                        "range and platform conditions."
                    )
                ],
                "reason": None,
            },
            {
                "proposition_id": (
                    "configuration.2018_12550.empty_or_comment_only_acl"
                ),
                "status": "F",
                "evidence_class": "CURRENT_DEPLOYMENT_EVIDENCE",
                "source": (
                    "output/evidence_runs/"
                    "mosquitto_acl_loaded_state_20261116T192251865Z.json"
                ),
                "evidence": [
                    (
                        "The running mosquitto-vuln-lab container used the "
                        "loaded configuration /mosquitto/config/mosquitto.conf "
                        "and listener 1883."
                    ),
                    (
                        "The loaded ACL file contained the active entries "
                        "'user sensoruser' and 'read iomt/vuln-test'."
                    ),
                    (
                        "Configuration and ACL hashes remained unchanged "
                        "during the recorded observation window."
                    ),
                ],
                "reason": (
                    "The empty/comment-only ACL trigger is ruled out for the "
                    "current observed window only; this is not an exploit test."
                ),
                "scope": observation["observation_window_utc"],
            },
            {
                "proposition_id": "attacker.2018_12550.client_access",
                "status": "U",
                "evidence_class": "EVIDENCE_GAP",
                "source": "No deployment-specific trigger validation",
                "evidence": [],
                "reason": (
                    "No observation establishes which client could create "
                    "the empty/comments-only ACL condition."
                ),
            },
            {
                "proposition_id": (
                    "transition.direct_mosquitto_2018_12550.current"
                ),
                "status": "T",
                "evidence_class": "CURRENT_DEPLOYMENT_EVIDENCE",
                "source": (
                    "output/evidence_runs/"
                    "mosquitto_acl_loaded_state_20261116T192251865Z.json"
                ),
                "evidence": [
                    (
                        "The direct Mosquitto deployment identity, running "
                        "process, listener and loaded configuration were "
                        "observed together in one time-scoped read-only window."
                    )
                ],
                "reason": None,
            },
            {
                "proposition_id": "capability.2018_12550.acl_bypass",
                "status": "U",
                "evidence_class": "EVIDENCE_GAP",
                "source": "No CVE-2018-12550 exploit test",
                "evidence": [],
                "reason": (
                    "No attempt was made to exploit an empty ACL file or "
                    "observe unauthorized broker operations."
                ),
            },
            {
                "proposition_id": (
                    "receiver.mosquitto.2018_12550.processing_and_controls"
                ),
                "status": "U",
                "evidence_class": "EVIDENCE_GAP",
                "source": "No receiver-processing evidence",
                "evidence": [],
                "reason": (
                    "No post-trigger authorization or receiver effect exists "
                    "for this deployment."
                ),
            },
            {
                "proposition_id": "target.mosquitto.12550.C",
                "status": "U",
                "evidence_class": "EVIDENCE_GAP",
                "source": "No target-impact evidence",
                "evidence": [],
                "reason": "No CVE-2018-12550 exploit was performed.",
            },
            {
                "proposition_id": "target.mosquitto.12550.I",
                "status": "U",
                "evidence_class": "EVIDENCE_GAP",
                "source": "No target-impact evidence",
                "evidence": [],
                "reason": "No CVE-2018-12550 exploit was performed.",
            },
            {
                "proposition_id": "target.mosquitto.12550.A",
                "status": "U",
                "evidence_class": "EVIDENCE_GAP",
                "source": "No target-impact evidence",
                "evidence": [],
                "reason": "No CVE-2018-12550 exploit was performed.",
            },
        ]
    )

    document.setdefault("research_decisions", []).append(
        {
            "decision_id": "CVE_2018_12550_CONFIGURATION_GATE_FALSE",
            "status": "APPLIED",
            "decision": (
                "The empty/comment-only ACL prerequisite is FALSE only for "
                "the observed current window. Version applicability remains "
                "AFFECTED, while exploit capability, receiver effects and "
                "target C/I/A remain UNKNOWN."
            ),
            "citations": [
                (
                    "output/evidence_runs/"
                    "mosquitto_acl_loaded_state_20261116T192251865Z.json"
                ),
                (
                    "output/ebsr_assessments/"
                    "ebsr-assessment-20261110T140855977011Z-v1.0.json"
                ),
            ],
        }
    )

    document.setdefault("scenarios", []).append(
        {
            "scenario_id": "RESEARCH-12550-MOSQUITTO",
            "attacker_id": "ATTACKER-12550-CLIENT-ACCESS-U",
            "target_deployment_id": "mosquitto-vuln-lab",
            "description": (
                "Direct CVE-2018-12550 scenario. The deployed ACL is observed "
                "to be non-empty in the current window; exploitation and "
                "target impact remain untested."
            ),
            "paths": [
                {
                    "path_id": "2018_12550-direct",
                    "target_deployment_id": "mosquitto-vuln-lab",
                    "target_channels": {
                        "C": {
                            "proposition_id": "target.mosquitto.12550.C"
                        },
                        "I": {
                            "proposition_id": "target.mosquitto.12550.I"
                        },
                        "A": {
                            "proposition_id": "target.mosquitto.12550.A"
                        },
                    },
                    "transitions": [
                        {
                            "step_id": "2018_12550-direct-step",
                            "source_deployment_id": "mosquitto-vuln-lab",
                            "target_deployment_id": "mosquitto-vuln-lab",
                            "transition_type": "DIRECT",
                            "cve_ids": ["CVE-2018-12550"],
                            "reproduction_grades": {
                                "CVE-2018-12550": "NOT_TESTED"
                            },
                            "conditions": {
                                "A": {
                                    "proposition_id": (
                                        "cve.2018_12550.applicability"
                                    )
                                },
                                "G": {
                                    "proposition_id": (
                                        "attacker.2018_12550.client_access"
                                    )
                                },
                                "H": {
                                    "proposition_id": (
                                        "configuration.2018_12550."
                                        "empty_or_comment_only_acl"
                                    )
                                },
                                "B": {
                                    "proposition_id": (
                                        "transition.direct_mosquitto_"
                                        "2018_12550.current"
                                    )
                                },
                                "K": {
                                    "proposition_id": (
                                        "capability.2018_12550.acl_bypass"
                                    )
                                },
                                "Y": {
                                    "proposition_id": (
                                        "receiver.mosquitto.2018_12550."
                                        "processing_and_controls"
                                    )
                                },
                            },
                        }
                    ],
                }
            ],
        }
    )
    document.setdefault("observations", []).append(
        {
            "observation_id": observation["observation_id"],
            "observation_class": "CURRENT_READ_ONLY_DEPLOYMENT_STATE",
            "deployment_id": "mosquitto-vuln-lab",
            "observation_window_utc": observation["observation_window_utc"],
            "listener": observation["listener"],
            "configuration_sha256": observation["configuration"]["sha256"],
            "acl_sha256": observation["acl"]["sha256"],
            "active_acl_rules": observation["acl"]["rules"],
            "empty_or_comment_only_acl": "FALSE",
            "scope_limit": (
                "Configuration-state observation only; no CVE trigger, "
                "receiver effect or target C/I/A impact was observed."
            ),
        }
    )

    OUTPUT_PATH.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return OUTPUT_PATH


if __name__ == "__main__":
    print(main())
