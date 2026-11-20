"""Build the v6 CVE-2018-12546 evidence-correction bundle from v5."""

from __future__ import annotations

import copy
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
V5_PATH = ROOT / "scenarios" / "ebsr_mosquitto_12546_12551_v5.json"
OUTPUT_PATH = ROOT / "scenarios" / "ebsr_mosquitto_12546_12551_v6.json"
MANUAL_RECORD = ROOT / "cve_2018_12546_test.py"
NVD_BASELINE = ROOT / "mosquitto_1.5.5_baseline_results.json"
CONTROL_BASELINE = ROOT / "mosquitto_2.1.2_baseline_results.json"


def proposition(document: dict, proposition_id: str) -> dict:
    matches = [
        item
        for item in document.get("evidence", [])
        if item.get("proposition_id") == proposition_id
    ]
    if len(matches) != 1:
        raise ValueError(f"Expected one proposition {proposition_id!r}.")
    return matches[0]


def main() -> Path:
    for required in (
        V5_PATH,
        MANUAL_RECORD,
        NVD_BASELINE,
        CONTROL_BASELINE,
    ):
        if not required.exists():
            raise FileNotFoundError(required)

    document = copy.deepcopy(
        json.loads(V5_PATH.read_text(encoding="utf-8-sig"))
    )
    document["assessment_version"] = (
        "research-mosquitto-2026-11-10-v6"
    )
    document["derived_from"] = {
        "assessment_version": "research-mosquitto-2026-11-10-v5",
        "path": "scenarios/ebsr_mosquitto_12546_12551_v5.json",
        "purpose": "CVE-2018-12546 evidence correction",
        "frozen_mathematics_changed": False,
    }

    decisions = [
        {
            "decision_id": "SPLIT_12546_DELIVERY_AND_CONTROLS",
            "status": "APPLIED",
            "decision": (
                "Historical subscriber delivery remains a manual observation, "
                "while mandatory receiver controls receive a separate UNKNOWN "
                "proposition because the saved artifact does not record a "
                "control comparison."
            ),
            "citations": [
                "cve_2018_12546_test.py",
                "scenarios/ebsr_mosquitto_12546_12551_v5.json",
            ],
        },
        {
            "decision_id": "DIRECT_12546_B_TIME_SCOPE_UNAVAILABLE",
            "status": "APPLIED",
            "decision": (
                "The direct Mosquitto transition remains UNKNOWN because the "
                "saved artifact contains no independent deployment identifier, "
                "timestamp, raw broker transcript or immutable run record."
            ),
            "citations": [
                "cve_2018_12546_test.py",
                "attack_simulation.py",
            ],
        },
        {
            "decision_id": "MOSQUITTO_12546_INTEGRITY_NOT_ESTABLISHED",
            "status": "APPLIED",
            "decision": (
                "Retained-message accessibility is not by itself evidence of "
                "a specific adverse integrity effect on Mosquitto. The target "
                "integrity channel remains UNKNOWN with interval [0,1]."
            ),
            "citations": [
                "cve_2018_12546_test.py",
                "scenarios/ebsr_mosquitto_12546_12551_v5.json",
            ],
        },
        {
            "decision_id": "HISTORICAL_12546_DELIVERY_GRADE_RETAINED",
            "status": "APPLIED",
            "decision": (
                "Historical subscriber delivery remains TRUE with reproduction "
                "grade MANUALLY_OBSERVED; it is not upgraded to independent "
                "reproduction."
            ),
            "citations": [
                "cve_2018_12546_test.py",
                "scenarios/ebsr_mosquitto_12546_12551_v5.json",
            ],
        },
    ]
    document.setdefault("research_decisions", []).extend(decisions)

    legacy_id = (
        "receiver.mosquitto.2018_12546."
        "retained_delivery_and_controls"
    )
    document["evidence"] = [
        item
        for item in document["evidence"]
        if item.get("proposition_id") != legacy_id
    ]

    delivery_id = (
        "observation.mosquitto.2018_12546."
        "historical_subscriber_delivery"
    )
    controls_id = "receiver.mosquitto.2018_12546.controls"
    document["evidence"].extend(
        [
            {
                "proposition_id": delivery_id,
                "status": "T",
                "evidence_class": "HISTORICAL_MANUAL_OBSERVATION",
                "source": "cve_2018_12546_test.py",
                "evidence": [
                    (
                        "The historical record states that a new subscriber "
                        "received the retained Temperature=36.8 message after "
                        "the publisher's ACL access changed."
                    )
                ],
                "reason": None,
                "reproduction_grade": "MANUALLY_OBSERVED",
                "independence": (
                    "No raw broker log, subscriber output or immutable run "
                    "artifact was preserved in the repository."
                ),
            },
            {
                "proposition_id": controls_id,
                "status": "U",
                "evidence_class": "EVIDENCE_GAP",
                "source": "No receiver-control comparison",
                "evidence": [],
                "reason": (
                    "Historical delivery does not establish whether the "
                    "intended post-revocation control worked, failed or was "
                    "not applicable. No matched control observation is saved."
                ),
            },
        ]
    )

    direct_transition = proposition(
        document,
        "transition.direct_mosquitto_2018_12546.current",
    )
    direct_transition["status"] = "U"
    direct_transition["evidence_class"] = "EVIDENCE_GAP"
    direct_transition["source"] = "No independently time-scoped run artifact"
    direct_transition["evidence"] = []
    direct_transition["reason"] = (
        "The historical summary does not provide an independent deployment "
        "identifier, run timestamp or immutable execution transcript proving "
        "the current direct transition. It remains UNKNOWN."
    )

    capability = proposition(
        document,
        "capability.2018_12546.direct_retained_access",
    )
    capability["evidence_class"] = "HISTORICAL_MANUAL_OBSERVATION"
    capability["source"] = "cve_2018_12546_test.py"
    capability["reason"] = None
    capability["reproduction_grade"] = "MANUALLY_OBSERVED"

    target_integrity = proposition(
        document,
        "target.mosquitto.12546.I",
    )
    target_integrity["status"] = "U"
    target_integrity["evidence_class"] = "EVIDENCE_GAP"
    target_integrity["source"] = "No specific Mosquitto integrity effect"
    target_integrity["evidence"] = []
    target_integrity["reason"] = (
        "Stale retained-content accessibility is not evidence of a specific "
        "adverse integrity effect on Mosquitto itself. The target interval is "
        "therefore [0,1]."
    )

    matching_scenarios = [
        scenario
        for scenario in document.get("scenarios", [])
        if scenario.get("scenario_id")
        == "RESEARCH-12546-MOSQUITTO"
    ]
    if len(matching_scenarios) != 1:
        raise ValueError("Expected one direct CVE-2018-12546 scenario.")
    direct_scenario = matching_scenarios[0]
    direct_scenario["description"] = (
        "Direct retained-message scenario corrected to separate historical "
        "delivery from untested receiver controls and unsupported target "
        "integrity."
    )
    if len(direct_scenario.get("paths", [])) != 1:
        raise ValueError("Expected one direct CVE-2018-12546 path.")
    direct_path = direct_scenario["paths"][0]
    transitions = direct_path.get("transitions", [])
    if len(transitions) != 1:
        raise ValueError("Expected one direct transition.")
    conditions = transitions[0]["conditions"]
    conditions["B"]["proposition_id"] = (
        "transition.direct_mosquitto_2018_12546.current"
    )
    conditions["Y"]["proposition_id"] = controls_id
    transitions[0]["reproduction_grades"] = {
        "CVE-2018-12546": "MANUALLY_OBSERVED"
    }

    correction_record = {
        "correction_id": "CVE-2018-12546-V6-EVIDENCE-SCOPE",
        "deployment_id": "mosquitto-vuln-lab",
        "cve_id": "CVE-2018-12546",
        "historical_delivery_proposition_id": delivery_id,
        "historical_delivery_status": "T",
        "historical_delivery_reproduction_grade": "MANUALLY_OBSERVED",
        "mandatory_receiver_controls_proposition_id": controls_id,
        "mandatory_receiver_controls_status": "U",
        "direct_transition_proposition_id": (
            "transition.direct_mosquitto_2018_12546.current"
        ),
        "direct_transition_status": "U",
        "target_integrity_proposition_id": "target.mosquitto.12546.I",
        "target_integrity_status": "U",
        "sources": [
            "cve_2018_12546_test.py",
            "mosquitto_1.5.5_baseline_results.json",
            "mosquitto_2.1.2_baseline_results.json",
        ],
        "reason": (
            "The historical note supports a manual delivery observation, but "
            "not an independently scoped direct run, receiver-control outcome "
            "or Mosquitto integrity consequence."
        ),
    }
    document.setdefault("evidence_corrections", []).append(correction_record)

    OUTPUT_PATH.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return OUTPUT_PATH


if __name__ == "__main__":
    print(main())
