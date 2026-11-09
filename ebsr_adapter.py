"""Evidence adapter from deployment assessments to the frozen EBSR evaluator.

This module performs no Docker, NVD, CPE or CVSS retrieval. It accepts a
JSON-friendly evidence bundle, resolves explicit deployment-scoped scenario
paths, and calls the pure functions in :mod:`ebsr`.

Input bundle (schema version 1.1)::

    {
      "schema_version": "1.1",
      "assessment_version": "1.0",
      "deployments": [
        {
          "deployment_id": "mosquitto-vuln-lab",
          "component_id": "mosquitto",
          "display_name": "Mosquitto Vulnerable Lab",
          "version": "1.5.5",
          "discovery_evidence": {...}
        }
      ],
      "attacker_profiles": [
        {"attacker_id": "A1", "description": "Explicit profile"}
      ],
      "architecture_evidence": [
        {
          "relationship_id": "mqtt-to-ditto",
          "source_deployment_id": "mosquitto-vuln-lab",
          "target_deployment_id": "ditto-prod",
          "transition_type": "DF",
          "status": "SUPPORTED",
          "evidence": ["..."],
          "notes": "..."
        }
      ],
      "evidence": [
        {
          "proposition_id": "deployment.mqtt.acl_enabled",
          "status": "T",
          "source": "configuration observation",
          "evidence": ["..."]
        }
      ],
      "cve_assessments": [
        {
          "deployment_id": "mosquitto-vuln-lab",
          "component_id": "mosquitto",
          "version": "1.5.5",
          "discovery_evidence": {...},
          "retrieval": {...},
          "affected": [
            {
              "cve_id": "CVE-...",
              "status": "AFFECTED",
              "cvss": {"primary": {"vector": "CVSS:3.1/..."}},
              "applicability": {...}
            }
          ],
          "unknown": [],
          "not_affected": []
        }
      ],
      "scenarios": [
        {
          "scenario_id": "S1",
          "attacker_id": "A1",
          "target_deployment_id": "ditto-prod",
          "description": "Explicit scenario",
          "paths": [
            {
              "path_id": "P1",
              "target_deployment_id": "influx-prod",
              "target_channels": {
                "C": {"state": "F", "evidence": ["..."]},
                "I": {"state": "T", "magnitude": [0.5, 0.7]},
                "A": {"state": "U", "evidence": ["..."]}
              },
              "transitions": [
                {
                  "step_id": "mqtt-to-ditto",
                  "source_deployment_id": "mosquitto-vuln-lab",
                  "target_deployment_id": "ditto-prod",
                  "transition_type": "DF",
                  "relationship_id": "mqtt-to-ditto",
                  "cve_ids": ["CVE-..."],
                  "conditions": {
                    "A": {"proposition_id": "cve.applicability"},
                    "G": {"proposition_id": "attacker.reachability"},
                    "H": {"status": "T", "evidence": ["..."]},
                    "K": {"proposition_id": "deployment.mqtt.acl_enabled"},
                    "Y": {"status": "T", "evidence": ["..."]}
                  }
                },
                {
                  "step_id": "ditto-to-influx",
                  "source_deployment_id": "ditto-prod",
                  "target_deployment_id": "influx-prod",
                  "transition_type": "LX",
                  "relationship_id": "ditto-to-influx",
                  "cve_ids": ["CVE-..."],
                  "conditions": {
                    "A": {"status": "T", "evidence": ["..."]},
                    "G": {"status": "T", "evidence": ["..."]},
                    "H": {"status": "T", "evidence": ["..."]},
                    "K": {"status": "T", "evidence": ["..."]},
                    "Y": {"status": "T", "evidence": ["..."]}
                  }
                }
              ]
            }
          ]
        }
      ],
      "validation_records": []
    }

The mandatory condition variables are A, G, H, B, K and Y for every
transition. Missing variables are inserted as UNKNOWN; they never become
TRUE through omission. Conditions may reference a shared proposition in
``evidence`` by ``proposition_id``; all assertions for that ID are reconciled,
so opposing evidence becomes CONFLICT in every dependent path. A may also be
supported by the deployment-specific CVE applicability record. For a
cross-deployment transition, B is never inferred from graph adjacency: every
record sharing the relationship ID is evaluated, and an explicit matching
DF/LX/CT type is required.

Transitions are ordered. Each transition names its own source and target
deployment, CVE IDs and conditions. The final transition's target is the
path target. Duplicate scenario, path, deployment, attacker or transition
step identifiers are not silently overwritten.

DF, LX and CT are transition descriptions only. They select no coefficients
or alternative equations in this adapter; the frozen EBSR equations remain
unchanged.
"""

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import re

import ebsr


SCHEMA_VERSION = "1.1"
CONDITION_VARIABLES = ("A", "G", "H", "B", "K", "Y")
TRANSITION_TYPES = ("DF", "LX", "CT", "DIRECT")
REPRODUCTION_GRADES = (
    "NOT_TESTED",
    "MANUALLY_OBSERVED",
    "INDEPENDENTLY_REPRODUCED",
    "REPRODUCTION_FAILED",
    "INCONCLUSIVE",
)

DEFAULT_OUTPUT_DIRECTORY = Path("output") / "ebsr_assessments"

_ARCHITECTURE_STATUS = {
    "SUPPORTED": ebsr.TRUE,
    "TRUE": ebsr.TRUE,
    "T": ebsr.TRUE,
    "NOT_SUPPORTED": ebsr.FALSE,
    "FALSE": ebsr.FALSE,
    "F": ebsr.FALSE,
    "UNKNOWN": ebsr.UNKNOWN,
    "U": ebsr.UNKNOWN,
    "CONFLICT": ebsr.CONFLICT,
    "X": ebsr.CONFLICT,
}


class EBSRAdapterError(ValueError):
    """Raised when an evidence bundle cannot be interpreted."""


def _now_utc():
    return datetime.now(timezone.utc).isoformat()


def _as_text(value):
    if value is None:
        return None
    return str(value)


def _evidence_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return deepcopy(value)
    return [deepcopy(value)]


def _state(value, default=ebsr.UNKNOWN):
    """Normalise an evidence state without changing EBSR precedence."""

    if value is None:
        return default
    if isinstance(value, dict):
        value = (
            value.get("status")
            or value.get("state")
            or value.get("evidence_state")
        )
        if value is None:
            return default
    try:
        return ebsr.combine_evidence([value], "AND")
    except (TypeError, ValueError) as exc:
        raise EBSRAdapterError(
            f"Unsupported evidence state: {value!r}"
        ) from exc


def _merge_evidence_states(states):
    """Merge independent statements about the same proposition conservatively.

    This is proposition-level evidence reconciliation, not a risk formula.
    Directly contradictory T/F statements remain CONFLICT; a definite FALSE
    still bounds an otherwise UNKNOWN statement, and any explicit CONFLICT is
    retained because it may concern a scenario-dependent condition.
    """

    states = list(states)
    if not states:
        return ebsr.UNKNOWN
    if ebsr.CONFLICT in states:
        return ebsr.CONFLICT
    if ebsr.TRUE in states and ebsr.FALSE in states:
        return ebsr.CONFLICT
    if ebsr.TRUE in states and ebsr.UNKNOWN in states:
        return ebsr.UNKNOWN
    if ebsr.FALSE in states:
        return ebsr.FALSE
    if ebsr.UNKNOWN in states:
        return ebsr.UNKNOWN
    return ebsr.TRUE


def canonical_proposition_id(
    scenario_id,
    path_id,
    variable,
    step_id=None,
):
    """Return a stable proposition ID for generated, path-local evidence."""

    parts = [scenario_id, path_id]
    if step_id:
        parts.append(step_id)
    parts.append(variable)
    return "::".join(str(part) for part in parts)


def _require_identifier(value, kind, context):
    if not isinstance(value, str) or not value.strip():
        raise EBSRAdapterError(
            f"{context} requires a non-empty string {kind}."
        )
    return value.strip()


def _add_proposition(propositions, proposition_id, record):
    """Add or reconcile a proposition without replacing existing evidence."""

    proposition_id = _require_identifier(
        proposition_id,
        "proposition_id",
        "Evidence",
    )
    existing = propositions.get(proposition_id)
    source_record = deepcopy(record)

    if existing is None:
        propositions[proposition_id] = {
            "status": source_record["status"],
            "sources": [source_record],
            "reason": source_record.get("reason"),
        }
        return proposition_id

    sources = list(existing.get("sources", []))
    sources.append(source_record)
    state = _merge_evidence_states(
        item.get("status", ebsr.UNKNOWN)
        for item in sources
    )
    reasons = [
        item.get("reason")
        for item in sources
        if item.get("reason")
    ]
    existing["status"] = state
    existing["sources"] = sources
    existing["reason"] = "; ".join(dict.fromkeys(reasons)) or None
    return proposition_id


def _condition_record(
    state,
    source,
    evidence=None,
    reason=None,
    source_value=None,
):
    return {
        "status": state,
        "source": source,
        "evidence": _evidence_list(evidence),
        "reason": reason,
        "source_value": deepcopy(source_value),
    }


def _condition_from_input(value):
    if value is None:
        return None
    if isinstance(value, str):
        return _condition_record(
            _state(value),
            "scenario_definition",
            source_value=value,
        )
    if not isinstance(value, dict):
        raise EBSRAdapterError(
            "A condition must be a state string or an evidence object."
        )

    state = _state(value)
    return _condition_record(
        state,
        value.get("source", "scenario_definition"),
        value.get("evidence", value.get("observations", [])),
        value.get("reason") or value.get("explanation"),
        value,
    )


def _shared_propositions(evidence_items):
    propositions = {}
    for index, item in enumerate(evidence_items or []):
        if not isinstance(item, dict):
            raise EBSRAdapterError(
                f"Evidence item {index} must be an object."
            )
        proposition_id = _require_identifier(
            item.get("proposition_id"),
            "proposition_id",
            f"Evidence item {index}",
        )
        record = _condition_record(
            _state(item),
            item.get("source", "shared_evidence"),
            item.get("evidence", item.get("observations", [])),
            item.get("reason") or item.get("explanation"),
            deepcopy(item),
        )
        _add_proposition(propositions, proposition_id, record)
    return propositions


def _condition_reference(
    value,
    fallback_id,
    propositions,
    context,
):
    """Resolve a condition to a shared or generated proposition ID."""

    if value is None:
        _add_proposition(
            propositions,
            fallback_id,
            _condition_record(
                ebsr.UNKNOWN,
                "adapter",
                reason=(
                    f"{context} omitted mandatory evidence; "
                    "the condition remains UNKNOWN."
                ),
            ),
        )
        return fallback_id

    if isinstance(value, str) and value in propositions:
        return value

    if isinstance(value, dict):
        reference = value.get("proposition_id")
        if reference:
            reference = _require_identifier(
                reference,
                "proposition_id",
                context,
            )
            if any(
                key in value
                for key in ("state", "status", "evidence_state")
            ):
                _add_proposition(
                    propositions,
                    reference,
                    _condition_from_input(value),
                )
            elif reference not in propositions:
                _add_proposition(
                    propositions,
                    reference,
                    _condition_record(
                        ebsr.UNKNOWN,
                        "adapter",
                        reason=(
                            f"{context} references evidence {reference!r} "
                            "that is not defined; it remains UNKNOWN."
                        ),
                    ),
                )
            return reference

    record = _condition_from_input(value)
    _add_proposition(
        propositions,
        fallback_id,
        record,
    )
    return fallback_id


def _assessment_rows(record):
    rows = []
    for group in ("affected", "affected_other_scale", "unknown", "not_affected"):
        for row in record.get(group, []) or []:
            if isinstance(row, dict) and row.get("cve_id"):
                item = deepcopy(row)
                item.setdefault("assessment_group", group)
                rows.append(item)
    return rows


def _index_cve_assessments(cve_assessments):
    index = {}
    for record in cve_assessments or []:
        if not isinstance(record, dict):
            continue
        deployment_id = record.get("deployment_id")
        for row in _assessment_rows(record):
            key = (deployment_id, row["cve_id"])
            index.setdefault(key, []).append({
                "record": record,
                "row": row,
            })
    return index


def _assessment_state(entries):
    states = []
    for entry in entries:
        row = entry["row"]
        status = row.get("status")
        if status == "AFFECTED":
            states.append(ebsr.TRUE)
        elif status == "NOT_AFFECTED":
            states.append(ebsr.FALSE)
        else:
            states.append(ebsr.UNKNOWN)
    return _merge_evidence_states(states)


def _affected_row(entries):
    for entry in entries:
        if entry["row"].get("status") == "AFFECTED":
            return entry["row"]
    return None


def _cve_vector(row):
    cvss = row.get("cvss", {})
    primary = cvss.get("primary") if isinstance(cvss, dict) else None
    if isinstance(primary, dict):
        return primary.get("vector")
    return row.get("cvss_vector")


def _validation_records_for(
    validation_records,
    deployment_id,
    cve_id,
):
    matches = []
    for record in validation_records or []:
        if not isinstance(record, dict):
            continue
        if record.get("cve_id") != cve_id:
            continue
        record_deployment = record.get("deployment_id")
        if record_deployment not in (None, deployment_id):
            continue
        matches.append(record)
    return matches


def _normalise_reproduction_grade(value):
    if value is None:
        return None
    normalised = str(value).strip().upper().replace(" ", "_")
    if normalised == "VALIDATED":
        # The existing controlled case is a manually recorded observation.
        # "VALIDATED" alone is not evidence of independent reproduction.
        return "MANUALLY_OBSERVED"
    if normalised == "NOT_REPRODUCED":
        return "REPRODUCTION_FAILED"
    if normalised in REPRODUCTION_GRADES:
        return normalised
    return "INCONCLUSIVE"


def _reproduction_evidence(
    path,
    deployment_id,
    cve_id,
    validation_records,
):
    grades = path.get("reproduction_grades", {})
    explicit = (
        grades.get(cve_id)
        if isinstance(grades, dict)
        else None
    )
    matches = _validation_records_for(
        validation_records,
        deployment_id,
        cve_id,
    )
    record = matches[0] if matches else None

    if explicit is not None:
        grade = _normalise_reproduction_grade(explicit) or "NOT_TESTED"
        source = "scenario_definition"
    elif record is not None:
        if record.get("independently_reproduced") is True:
            grade = "INDEPENDENTLY_REPRODUCED"
        else:
            grade = _normalise_reproduction_grade(
                record.get("reproduction_grade")
                or record.get("validation_status")
            ) or "MANUALLY_OBSERVED"
        source = "validation_record"
    else:
        grade = "NOT_TESTED"
        source = "default"

    return {
        "grade": grade,
        "source": source,
        "validation_record": deepcopy(record),
    }


def _relationship_state(
    architecture_evidence,
    relationship_id,
    source_deployment_id,
    target_deployment_id,
    transition_type,
):
    """Reconcile every relationship record sharing the requested ID."""

    if not relationship_id:
        return (
            ebsr.UNKNOWN,
            "No explicit architecture relationship ID was bound.",
            [],
        )

    matches = [
        relationship
        for relationship in architecture_evidence or []
        if (
            isinstance(relationship, dict)
            and relationship.get("relationship_id") == relationship_id
        )
    ]

    if not matches:
        return (
            ebsr.UNKNOWN,
            f"No architecture evidence exists for {relationship_id!r}.",
            [],
        )

    states = []
    reasons = []

    for relationship in matches:

        source_id = relationship.get("source_deployment_id")
        target_id = relationship.get("target_deployment_id")
        explicit_type = relationship.get("transition_type")
        legacy_type = relationship.get("relationship_type")
        relationship_type = str(
            explicit_type or legacy_type or ""
        ).upper()

        if not explicit_type or (
            explicit_type is None
            and relationship_type not in TRANSITION_TYPES
        ):
            states.append(ebsr.UNKNOWN)
            reasons.append(
                "A relationship record has no explicit DF/LX/CT "
                "transition type."
            )
            continue

        if source_id != source_deployment_id or target_id != target_deployment_id:
            states.append(ebsr.CONFLICT)
            reasons.append(
                "Relationship records disagree with the path endpoints."
            )
            continue

        if relationship_type != transition_type:
            states.append(ebsr.CONFLICT)
            reasons.append(
                "Relationship records disagree with the path transition type."
            )
            continue

        raw_status = str(
            relationship.get("status", "UNKNOWN")
        ).upper()

        if raw_status not in _ARCHITECTURE_STATUS:
            states.append(ebsr.UNKNOWN)
            reasons.append(
                f"Unsupported relationship status: {raw_status}"
            )
            continue

        state = _ARCHITECTURE_STATUS[raw_status]
        evidence = _evidence_list(relationship.get("evidence"))

        if state == ebsr.TRUE and not evidence:
            states.append(ebsr.UNKNOWN)
            reasons.append(
                "A supported relationship lacks recorded evidence."
            )
            continue

        states.append(state)
        if relationship.get("notes"):
            reasons.append(relationship["notes"])

    return (
        _merge_evidence_states(states),
        "; ".join(dict.fromkeys(reasons)) or None,
        deepcopy(matches),
    )


def _channel_record(value):
    if value is None:
        return _condition_record(
            ebsr.UNKNOWN,
            "adapter",
            reason="No target-channel evidence was supplied.",
        )

    if isinstance(value, str):
        return _condition_record(
            _state(value),
            "scenario_definition",
            source_value=value,
        )

    if not isinstance(value, dict):
        raise EBSRAdapterError(
            "Target C/I/A evidence must be a state string or object."
        )

    if not any(
        key in value
        for key in ("state", "status", "evidence_state")
    ):
        reason = (
            "A magnitude without an established consequence state "
            "does not establish target impact."
        )
        state = ebsr.UNKNOWN
    else:
        state = _state(value)
        reason = value.get("reason") or value.get("explanation")

    return _condition_record(
        state,
        value.get("source", "scenario_definition"),
        value.get("evidence", value.get("observations", [])),
        reason,
        {
            "magnitude": deepcopy(value.get("magnitude")),
            "raw": deepcopy(value),
        },
    )


def _channel_spec(proposition_id, value):
    spec = {"proposition_id": proposition_id}
    if isinstance(value, dict) and value.get("magnitude") is not None:
        spec["magnitude"] = deepcopy(value["magnitude"])
    return spec


def _step_cve_ids(step):
    cve_ids = step.get("cve_ids")
    if cve_ids is None:
        cve_ids = []
        if step.get("cve_id"):
            cve_ids.append(step["cve_id"])
        for vulnerability_step in (
            step.get("vulnerability_steps", []) or []
        ):
            if (
                isinstance(vulnerability_step, dict)
                and vulnerability_step.get("cve_id")
            ):
                cve_ids.append(vulnerability_step["cve_id"])
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]
    return list(dict.fromkeys(
        cve_id for cve_id in cve_ids or [] if cve_id
    ))


def _normalise_transitions(scenario, path):
    """Return explicit ordered transition specifications."""

    path_id = path.get("path_id")
    transitions = path.get("transitions")

    if transitions is None:
        legacy_target = (
            path.get("target_deployment_id")
            or scenario.get("target_deployment_id")
        )
        transitions = [{
            "step_id": path.get("step_id") or f"{path_id}::transition",
            "source_deployment_id": (
                path.get("source_deployment_id")
                or legacy_target
            ),
            "target_deployment_id": legacy_target,
            "transition_type": path.get("transition_type"),
            "relationship_id": path.get("relationship_id"),
            "cve_ids": _step_cve_ids(path),
            "conditions": path.get("conditions", {}),
            "reproduction_grades": path.get(
                "reproduction_grades",
                {},
            ),
            "transition_description": path.get(
                "transition_description"
            ),
        }]

    if not isinstance(transitions, list) or not transitions:
        raise EBSRAdapterError(
            f"Path {path_id} requires at least one explicit transition."
        )

    normalised = []
    seen_steps = set()
    previous_target = None

    for index, transition in enumerate(transitions):
        if not isinstance(transition, dict):
            raise EBSRAdapterError(
                f"Path {path_id} transition {index} must be an object."
            )

        step_id = _require_identifier(
            transition.get("step_id"),
            "step_id",
            f"Path {path_id} transition {index}",
        )
        if step_id in seen_steps:
            raise EBSRAdapterError(
                f"Path {path_id} repeats transition step_id {step_id!r}."
            )
        seen_steps.add(step_id)

        source_deployment_id = _require_identifier(
            transition.get("source_deployment_id"),
            "source_deployment_id",
            f"Transition {step_id}",
        )
        target_deployment_id = _require_identifier(
            transition.get("target_deployment_id"),
            "target_deployment_id",
            f"Transition {step_id}",
        )
        transition_type = _require_identifier(
            transition.get("transition_type"),
            "transition_type",
            f"Transition {step_id}",
        ).upper()

        if transition_type not in TRANSITION_TYPES:
            raise EBSRAdapterError(
                f"Transition {step_id} has unsupported type "
                f"{transition_type!r}."
            )

        if (
            previous_target is not None
            and source_deployment_id != previous_target
        ):
            raise EBSRAdapterError(
                f"Path {path_id} is not an ordered deployment chain: "
                f"{previous_target!r} does not connect to "
                f"{source_deployment_id!r}."
            )

        item = deepcopy(transition)
        item.update({
            "step_id": step_id,
            "source_deployment_id": source_deployment_id,
            "target_deployment_id": target_deployment_id,
            "transition_type": transition_type,
            "cve_ids": _step_cve_ids(transition),
            "conditions": transition.get("conditions", {}) or {},
        })
        normalised.append(item)
        previous_target = target_deployment_id

    explicit_target = (
        path.get("target_deployment_id")
        or scenario.get("target_deployment_id")
    )
    final_target = normalised[-1]["target_deployment_id"]

    if explicit_target and explicit_target != final_target:
        raise EBSRAdapterError(
            f"Path {path_id} final target {final_target!r} does not match "
            f"declared target {explicit_target!r}."
        )

    return normalised


def _assemble_path(
    scenario,
    path,
    deployments,
    attacker_ids,
    relationships,
    cve_index,
    validation_records,
    propositions,
    ambiguous_deployments=None,
):
    scenario_id = scenario.get("scenario_id")
    path_id = path.get("path_id")
    path_id = _require_identifier(
        path_id,
        "path_id",
        "Scenario path",
    )
    transitions = _normalise_transitions(scenario, path)
    vulnerability_steps = []
    source_impacts = []
    reproduction_trace = {}
    action_steps = []
    transition_trace = []
    all_condition_ids = []
    all_cve_ids = []
    cve_deployment_ids = {}

    for transition_index, transition in enumerate(transitions):
        step_id = transition["step_id"]
        source_deployment_id = transition["source_deployment_id"]
        target_deployment_id = transition["target_deployment_id"]
        transition_type = transition["transition_type"]
        relationship_id = transition.get("relationship_id")

        if (
            source_deployment_id in (ambiguous_deployments or set())
            or target_deployment_id in (ambiguous_deployments or set())
        ):
            raise EBSRAdapterError(
                f"Transition {step_id} uses an ambiguous deployment ID."
            )
        if source_deployment_id not in deployments:
            raise EBSRAdapterError(
                f"Transition {step_id} source deployment is not present: "
                f"{source_deployment_id}"
            )
        if target_deployment_id not in deployments:
            raise EBSRAdapterError(
                f"Transition {step_id} target deployment is not present: "
                f"{target_deployment_id}"
            )

        if (
            source_deployment_id == target_deployment_id
            and transition_type != "DIRECT"
        ):
            raise EBSRAdapterError(
                f"Self-transition {step_id} must use DIRECT."
            )
        if (
            source_deployment_id != target_deployment_id
            and transition_type == "DIRECT"
        ):
            raise EBSRAdapterError(
                f"Cross-deployment transition {step_id} cannot use DIRECT."
            )

        cve_ids = transition["cve_ids"]
        applicability_states = []

        for cve_id in cve_ids:
            entries = cve_index.get(
                (source_deployment_id, cve_id),
                [],
            )
            row = _affected_row(entries)
            if row is None:
                raise EBSRAdapterError(
                    f"Transition {step_id} references {cve_id}, but "
                    f"deployment {source_deployment_id} has no confirmed "
                    "AFFECTED record."
                )

            vector = _cve_vector(row)
            reproduction = _reproduction_evidence(
                transition,
                source_deployment_id,
                cve_id,
                validation_records,
            )
            reproduction_trace[
                f"{source_deployment_id}::{cve_id}"
            ] = reproduction
            source_impact = ebsr.calculate_source_impact(vector)
            source_impacts.append({
                "deployment_id": source_deployment_id,
                "cve_id": cve_id,
                "cvss_v31_vector": vector,
                "source_impact": source_impact,
                "note": (
                    "Source C/I/A weights and composite index are retained "
                    "separately and are not target impact."
                ),
            })
            vulnerability_steps.append({
                "cve_id": cve_id,
                "component": (
                    deployments[source_deployment_id].get("component_id")
                    or source_deployment_id
                ),
                "deployment_id": source_deployment_id,
                "transition_step_id": step_id,
                "cvss_vector": vector,
                "condition_ids": [],
                "reproduction_grade": reproduction["grade"],
            })
            applicability_states.append(
                _assessment_state(entries)
            )
            cve_deployment_ids[cve_id] = source_deployment_id
            all_cve_ids.append(cve_id)

        step_conditions = transition.get("conditions", {})
        if not isinstance(step_conditions, dict):
            raise EBSRAdapterError(
                f"Transition {step_id} conditions must be an object."
            )

        relationship_records = []
        relationship_proposition_id = None

        if source_deployment_id != target_deployment_id:
            (
                architecture_state,
                architecture_reason,
                relationship_records,
            ) = _relationship_state(
                relationships,
                relationship_id,
                source_deployment_id,
                target_deployment_id,
                transition_type,
            )
            relationship_proposition_id = canonical_proposition_id(
                scenario_id,
                path_id,
                "B_relationship",
                step_id,
            )
            _add_proposition(
                propositions,
                relationship_proposition_id,
                _condition_record(
                    architecture_state,
                    "architecture_evidence",
                    evidence=[
                        deepcopy(record.get("evidence", []))
                        for record in relationship_records
                    ],
                    reason=architecture_reason,
                    source_value=relationship_records,
                ),
            )

        condition_refs = {}
        action_condition_ids = []

        for variable in CONDITION_VARIABLES:
            fallback_id = canonical_proposition_id(
                scenario_id,
                path_id,
                variable,
                step_id,
            )
            if (
                variable == "B"
                and relationship_proposition_id is not None
                and step_conditions.get(variable) is None
            ):
                reference_id = relationship_proposition_id
            else:
                reference_id = _condition_reference(
                    step_conditions.get(variable),
                    fallback_id,
                    propositions,
                    f"Transition {step_id} condition {variable}",
                )
            condition_refs[variable] = reference_id
            action_condition_ids.append(reference_id)

        if applicability_states:
            applicability_id = canonical_proposition_id(
                scenario_id,
                path_id,
                "A_applicability",
                step_id,
            )
            _add_proposition(
                propositions,
                applicability_id,
                _condition_record(
                    _merge_evidence_states(applicability_states),
                    "deployment_cve_assessment",
                    evidence=[
                        {
                            "deployment_id": source_deployment_id,
                            "cve_id": cve_id,
                            "status": _assessment_state(
                                cve_index.get(
                                    (source_deployment_id, cve_id),
                                    [],
                                )
                            ),
                        }
                        for cve_id in cve_ids
                    ],
                    reason=(
                        "Derived from deployment-specific CVE applicability."
                    ),
                ),
            )
            action_condition_ids.append(applicability_id)

        if relationship_proposition_id is not None:
            action_condition_ids.append(
                relationship_proposition_id
            )

        unique_action_conditions = list(dict.fromkeys(
            action_condition_ids
        ))
        all_condition_ids.extend(unique_action_conditions)
        action_steps.append({
            "step_id": step_id,
            "mechanism": transition_type,
            "condition_ids": unique_action_conditions,
            "description": transition.get(
                "transition_description"
            ),
            "order": transition_index,
            "source_deployment_id": source_deployment_id,
            "target_deployment_id": target_deployment_id,
            "relationship_id": relationship_id,
            "cve_ids": list(cve_ids),
        })
        transition_trace.append({
            "step_id": step_id,
            "order": transition_index,
            "source_deployment_id": source_deployment_id,
            "target_deployment_id": target_deployment_id,
            "transition_type": transition_type,
            "relationship_id": relationship_id,
            "relationship_records": deepcopy(relationship_records),
            "cve_ids": list(cve_ids),
            "condition_proposition_ids": dict(condition_refs),
            "action_condition_ids": unique_action_conditions,
        })

    target_input = path.get("target_channels", {}) or {}
    if not isinstance(target_input, dict):
        raise EBSRAdapterError(
            f"Path {path_id} target_channels must be an object."
        )

    target_specs = {}
    target_trace = {}

    for channel in ebsr.CHANNELS:
        value = target_input.get(channel)
        shared_id = None
        if isinstance(value, str) and value in propositions:
            shared_id = value
        elif (
            isinstance(value, dict)
            and value.get("proposition_id")
        ):
            shared_id = _require_identifier(
                value["proposition_id"],
                "proposition_id",
                f"Target channel {channel}",
            )
            if any(
                key in value
                for key in ("state", "status", "evidence_state")
            ):
                _add_proposition(
                    propositions,
                    shared_id,
                    _condition_from_input(value),
                )
            elif shared_id not in propositions:
                _add_proposition(
                    propositions,
                    shared_id,
                    _condition_record(
                        ebsr.UNKNOWN,
                        "adapter",
                        reason=(
                            f"Target channel {channel} references undefined "
                            f"evidence {shared_id!r}; it remains UNKNOWN."
                        ),
                    ),
                )

        if shared_id:
            proposition_id = shared_id
            record = deepcopy(propositions[shared_id])
        else:
            proposition_id = canonical_proposition_id(
                scenario_id,
                path_id,
                f"target_{channel}",
            )
            record = _channel_record(value)
            _add_proposition(
                propositions,
                proposition_id,
                record,
            )

        target_specs[channel] = _channel_spec(
            proposition_id,
            value,
        )
        target_trace[channel] = deepcopy(record)

    condition_ids = list(dict.fromkeys(all_condition_ids))
    first_transition = transitions[0]
    final_transition = transitions[-1]
    path_type = (
        first_transition["transition_type"]
        if len(transitions) == 1
        else "CHAIN"
    )

    ebsr_path = {
        "path_id": path_id,
        "condition_ids": condition_ids,
        "vulnerability_steps": vulnerability_steps,
        "action_steps": action_steps,
        "target_channels": target_specs,
        "source_deployment_id": first_transition[
            "source_deployment_id"
        ],
        "target_deployment_id": final_transition[
            "target_deployment_id"
        ],
        "transition_type": path_type,
        "transition_types": [
            transition["transition_type"]
            for transition in transitions
        ],
        "relationship_ids": [
            transition.get("relationship_id")
            for transition in transitions
            if transition.get("relationship_id")
        ],
        "transitions": transition_trace,
        "cve_ids": all_cve_ids,
        "cve_deployment_ids": cve_deployment_ids,
        "source_impacts": source_impacts,
        "target_evidence_trace": target_trace,
        "reproduction_evidence": reproduction_trace,
    }

    return ebsr_path, all_cve_ids


def _not_assessed_reason(record, retrieval):
    reasons = []
    if retrieval.get("status") in ("FAILED", "MALFORMED", None):
        reasons.append(
            "The deployment CVE retrieval is not complete or reliable."
        )
    reasons.append(
        "No matching scenario definition covered this affected CVE."
    )
    if record.get("reason"):
        reasons.append(record["reason"])
    return " ".join(reasons)


def _build_not_assessed(cve_assessments, covered):
    result = []
    for assessment in cve_assessments or []:
        deployment_id = assessment.get("deployment_id")
        retrieval = assessment.get("retrieval") or {}
        for row in _assessment_rows(assessment):
            key = (deployment_id, row.get("cve_id"))
            if key in covered:
                continue
            if row.get("status") not in ("AFFECTED", "UNKNOWN"):
                continue
            result.append({
                "deployment_id": deployment_id,
                "component_id": assessment.get("component_id"),
                "cve_id": row.get("cve_id"),
                "applicability_status": row.get("status"),
                "status": "NOT_ASSESSED",
                "reason": _not_assessed_reason(row, retrieval),
                "retrieval_status": retrieval.get("status"),
                "applicability_reason": row.get("reason"),
                "applicability": deepcopy(
                    row.get("applicability")
                ),
            })
    return result


def _evidence_gaps(input_document):
    gaps = []
    for assessment in input_document.get("cve_assessments", []) or []:
        retrieval = assessment.get("retrieval") or {}
        if retrieval.get("status") != "COMPLETE":
            gaps.append({
                "deployment_id": assessment.get("deployment_id"),
                "kind": "CVE_RETRIEVAL",
                "status": retrieval.get("status"),
                "detail": (
                    retrieval.get("error")
                    or "Retrieval completeness was not established."
                ),
            })
    for scenario in input_document.get("scenarios", []) or []:
        if not isinstance(scenario, dict):
            continue
        for path in scenario.get("paths", []) or []:
            if not isinstance(path, dict):
                continue
            transitions = path.get("transitions")
            if transitions is None:
                transitions = [{
                    "step_id": path.get("step_id"),
                    "source_deployment_id": path.get(
                        "source_deployment_id"
                    ),
                    "target_deployment_id": (
                        path.get("target_deployment_id")
                        or scenario.get("target_deployment_id")
                    ),
                    "transition_type": path.get("transition_type"),
                    "relationship_id": path.get("relationship_id"),
                }]
            for transition in transitions:
                if not isinstance(transition, dict):
                    continue
                if (
                    transition.get("source_deployment_id")
                    != transition.get("target_deployment_id")
                    and not transition.get("relationship_id")
                ):
                    gaps.append({
                        "scenario_id": scenario.get("scenario_id"),
                        "path_id": path.get("path_id"),
                        "step_id": transition.get("step_id"),
                        "kind": "ARCHITECTURE_RELATIONSHIP",
                        "detail": (
                            "No explicit architecture relationship was "
                            "supplied; B remains UNKNOWN."
                        ),
                    })
                if not transition.get("transition_type"):
                    gaps.append({
                        "scenario_id": scenario.get("scenario_id"),
                        "path_id": path.get("path_id"),
                        "step_id": transition.get("step_id"),
                        "kind": "TRANSITION_TYPE",
                        "detail": (
                            "The transition has no explicit DF/LX/CT type."
                        ),
                    })
    return gaps


def _index_unique_records(records, identifier, label):
    """Index records while exposing duplicate and invalid identifiers."""

    index = {}
    errors = []
    ambiguous = set()

    for position, record in enumerate(records or []):
        if not isinstance(record, dict):
            errors.append({
                "kind": "INPUT_IDENTIFIER",
                "record_type": label,
                "position": position,
                "reason": f"{label} record must be an object.",
            })
            continue

        value = record.get(identifier)
        if not isinstance(value, str) or not value.strip():
            errors.append({
                "kind": "INPUT_IDENTIFIER",
                "record_type": label,
                "position": position,
                "reason": (
                    f"{label} requires a non-empty string {identifier}."
                ),
            })
            continue

        value = value.strip()

        if value in index:
            ambiguous.add(value)
            errors.append({
                "kind": "DUPLICATE_IDENTIFIER",
                "record_type": label,
                "identifier": value,
                "reason": (
                    f"Duplicate {label} {identifier} {value!r}; "
                    "records using it are treated as ambiguous."
                ),
            })
            continue

        index[value] = record

    return index, errors, ambiguous


def build_assessment(input_document, generated_at=None):
    """Evaluate a complete evidence bundle with the frozen EBSR functions."""

    if not isinstance(input_document, dict):
        raise EBSRAdapterError(
            "The EBSR evidence bundle must be a JSON object."
        )

    document = deepcopy(input_document)
    deployments_list = document.get("deployments", []) or []
    (
        deployments,
        deployment_errors,
        ambiguous_deployments,
    ) = _index_unique_records(
        deployments_list,
        "deployment_id",
        "deployment",
    )
    (
        attacker_index,
        attacker_errors,
        ambiguous_attackers,
    ) = _index_unique_records(
        document.get("attacker_profiles", []) or [],
        "attacker_id",
        "attacker profile",
    )
    attacker_profiles = list(attacker_index.values())
    attacker_ids = set(attacker_index)
    relationships = [
        relationship
        for relationship in document.get("architecture_evidence", []) or []
        if isinstance(relationship, dict)
    ]
    cve_assessments = [
        assessment
        for assessment in document.get("cve_assessments", []) or []
        if isinstance(assessment, dict)
    ]
    validation_records = [
        record
        for record in document.get("validation_records", []) or []
        if isinstance(record, dict)
    ]
    scenarios = document.get("scenarios", []) or []
    evidence_items = document.get("evidence", []) or []

    if not isinstance(scenarios, list):
        raise EBSRAdapterError("scenarios must be a list.")
    if not isinstance(evidence_items, list):
        raise EBSRAdapterError("evidence must be a list.")

    cve_index = _index_cve_assessments(cve_assessments)
    propositions = _shared_propositions(evidence_items)
    scenario_results = []
    scenario_definitions = []
    scenario_errors = deployment_errors + attacker_errors
    target_profiles = []
    decision_trace = []
    coverage = set()
    target_metadata = {}
    seen_scenarios = set()
    seen_paths = set()

    for scenario in scenarios:
        if not isinstance(scenario, dict):
            scenario_errors.append({
                "scenario_id": None,
                "reason": "Scenario definition must be an object.",
            })
            continue

        scenario_id = scenario.get("scenario_id")
        if isinstance(scenario_id, str):
            scenario_id = scenario_id.strip()
        attacker_id = scenario.get("attacker_id")
        if isinstance(attacker_id, str):
            attacker_id = attacker_id.strip()
        target_deployment_id = scenario.get("target_deployment_id")
        paths = scenario.get("paths", []) or []

        if not scenario_id:
            scenario_errors.append({
                "scenario_id": None,
                "reason": "Scenario requires scenario_id.",
            })
            continue
        if scenario_id in seen_scenarios:
            scenario_errors.append({
                "scenario_id": scenario_id,
                "reason": (
                    f"Duplicate scenario_id {scenario_id!r}; this "
                    "definition was not evaluated."
                ),
            })
            continue
        seen_scenarios.add(scenario_id)
        if (
            attacker_id in ambiguous_attackers
            or any(
                deployment_id in ambiguous_deployments
                for deployment_id in (
                    scenario.get("target_deployment_id"),
                )
                if deployment_id
            )
        ):
            scenario_errors.append({
                "scenario_id": scenario_id,
                "reason": "Scenario uses an ambiguous input identifier.",
            })
            continue
        if attacker_id not in attacker_ids:
            scenario_errors.append({
                "scenario_id": scenario_id,
                "reason": (
                    f"Attacker profile {attacker_id!r} is not explicitly "
                    "defined."
                ),
            })
            continue
        if not paths:
            scenario_errors.append({
                "scenario_id": scenario_id,
                "reason": "Scenario requires at least one explicit path.",
            })
            continue

        assembled_paths = []
        path_cves = {}

        for raw_path in paths:
            if not isinstance(raw_path, dict):
                scenario_errors.append({
                    "scenario_id": scenario_id,
                    "reason": "Every scenario path must be an object.",
                })
                continue

            raw_path_id = raw_path.get("path_id")
            if (
                not isinstance(raw_path_id, str)
                or not raw_path_id.strip()
            ):
                scenario_errors.append({
                    "scenario_id": scenario_id,
                    "reason": "Every path requires a non-empty path_id.",
                })
                continue
            raw_path_id = raw_path_id.strip()

            if raw_path_id in seen_paths:
                scenario_errors.append({
                    "scenario_id": scenario_id,
                    "path_id": raw_path_id,
                    "reason": (
                        f"Duplicate path_id {raw_path_id!r}; this path "
                        "was not evaluated."
                    ),
                })
                continue
            seen_paths.add(raw_path_id)

            try:
                path, cve_ids = _assemble_path(
                    scenario,
                    raw_path,
                    deployments,
                    attacker_ids,
                    relationships,
                    cve_index,
                    validation_records,
                    propositions,
                    ambiguous_deployments,
                )
            except EBSRAdapterError as exc:
                scenario_errors.append({
                    "scenario_id": scenario_id,
                    "path_id": raw_path.get("path_id"),
                    "reason": str(exc),
                })
                continue

            target_deployment_id = (
                target_deployment_id
                or path["target_deployment_id"]
            )
            if path["target_deployment_id"] != target_deployment_id:
                scenario_errors.append({
                    "scenario_id": scenario_id,
                    "path_id": path.get("path_id"),
                    "reason": (
                        "A single scenario must target one explicit "
                        "deployment; use separate scenarios for separate "
                        "target profiles."
                    ),
                })
                continue

            assembled_paths.append(path)
            path_cves[path["path_id"]] = cve_ids

        if not assembled_paths:
            continue

        ebsr_scenario = {
            "scenario_id": scenario_id,
            "attacker_id": attacker_id,
            "target_component": target_deployment_id,
            "paths": assembled_paths,
        }

        try:
            result = ebsr.evaluate_scenario(
                ebsr_scenario,
                propositions,
            )
        except (TypeError, ValueError) as exc:
            scenario_errors.append({
                "scenario_id": scenario_id,
                "reason": f"EBSR evaluation rejected the scenario: {exc}",
            })
            continue

        assembled_by_path = {
            path["path_id"]: path for path in assembled_paths
        }
        for evaluated_path in result["paths"]:
            specification = assembled_by_path[evaluated_path["path_id"]]
            evaluated_path.update({
                "source_deployment_id": specification[
                    "source_deployment_id"
                ],
                "target_deployment_id": specification[
                    "target_deployment_id"
                ],
                "transition_type": specification["transition_type"],
                "transition_types": deepcopy(
                    specification["transition_types"]
                ),
                "relationship_ids": deepcopy(
                    specification["relationship_ids"]
                ),
                "transitions": deepcopy(
                    specification["transitions"]
                ),
                "vulnerability_steps": deepcopy(
                    specification["vulnerability_steps"]
                ),
                "action_steps": deepcopy(
                    specification["action_steps"]
                ),
                "condition_ids": list(
                    specification["condition_ids"]
                ),
                "cve_deployment_ids": deepcopy(
                    specification["cve_deployment_ids"]
                ),
                "source_impacts": deepcopy(
                    specification["source_impacts"]
                ),
                "target_evidence_trace": deepcopy(
                    specification["target_evidence_trace"]
                ),
                "reproduction_evidence": deepcopy(
                    specification["reproduction_evidence"]
                ),
            })

        result.update({
            "deployment_id": target_deployment_id,
            "component_id": deployments[target_deployment_id].get(
                "component_id"
            ),
            "description": scenario.get("description"),
            "source_deployments": sorted({
                transition["source_deployment_id"]
                for path in assembled_paths
                for transition in path["transitions"]
            }),
            "transition_types": sorted({
                transition_type
                for path in assembled_paths
                for transition_type in path["transition_types"]
            }),
            "decision_trace": [
                {
                    "path_id": path["path_id"],
                    "source_deployment_id": path[
                        "source_deployment_id"
                    ],
                    "target_deployment_id": path[
                        "target_deployment_id"
                    ],
                    "cve_ids": path_cves[path["path_id"]],
                    "cve_deployment_ids": path[
                        "cve_deployment_ids"
                    ],
                    "transitions": path["transitions"],
                    "condition_ids": path["condition_ids"],
                    "source_impacts": path["source_impacts"],
                    "target_evidence": path["target_evidence_trace"],
                    "reproduction_evidence": path[
                        "reproduction_evidence"
                    ],
                }
                for path in assembled_paths
            ],
        })
        scenario_results.append(result)
        for path_result in result["paths"]:
            target_profile = {
                "scenario_id": scenario_id,
                "path_id": path_result["path_id"],
                "attacker_id": attacker_id,
                "source_deployment_id": path_result[
                    "source_deployment_id"
                ],
                "target_deployment_id": path_result[
                    "target_deployment_id"
                ],
                "target_component_id": deployments[
                    path_result["target_deployment_id"]
                ].get("component_id"),
                "transition_type": path_result["transition_type"],
                "transition_types": deepcopy(
                    path_result["transition_types"]
                ),
                "transitions": deepcopy(
                    path_result["transitions"]
                ),
                "C": {
                    "evidence": path_result[
                        "target_evidence_trace"
                    ]["C"],
                    "result": path_result["target_impact"]["C"],
                },
                "I": {
                    "evidence": path_result[
                        "target_evidence_trace"
                    ]["I"],
                    "result": path_result["target_impact"]["I"],
                },
                "A": {
                    "evidence": path_result[
                        "target_evidence_trace"
                    ]["A"],
                    "result": path_result["target_impact"]["A"],
                },
            }
            target_profiles.append(target_profile)
            decision_trace.append({
                "scenario_id": scenario_id,
                "path_id": path_result["path_id"],
                "attacker_id": attacker_id,
                "source_deployment_id": path_result[
                    "source_deployment_id"
                ],
                "target_deployment_id": path_result[
                    "target_deployment_id"
                ],
                "transition_type": path_result["transition_type"],
                "transition_types": deepcopy(
                    path_result["transition_types"]
                ),
                "transitions": deepcopy(
                    path_result["transitions"]
                ),
                "cve_deployment_ids": deepcopy(
                    path_result["cve_deployment_ids"]
                ),
                "condition_propositions": {
                    proposition_id: deepcopy(
                        propositions[proposition_id]
                    )
                    for proposition_id in path_result[
                        "condition_ids"
                    ]
                },
                "source_impacts": path_result["source_impacts"],
                "target_profile": target_profile,
                "feasibility": path_result["feasibility"],
                "reproduction_grades": path_result[
                    "reproduction_grades"
                ],
            })
        scenario_definitions.append({
            "scenario_id": scenario_id,
            "attacker_id": attacker_id,
            "target_deployment_id": target_deployment_id,
            "description": scenario.get("description"),
            "paths": deepcopy(paths),
        })
        target_metadata[target_deployment_id] = {
            "deployment_id": target_deployment_id,
            "component_id": deployments[target_deployment_id].get(
                "component_id"
            ),
            "display_name": deployments[target_deployment_id].get(
                "display_name"
            ),
            "version": deployments[target_deployment_id].get("version"),
            "discovery_evidence": deepcopy(
                deployments[target_deployment_id].get(
                    "discovery_evidence"
                )
            ),
        }
        for path in assembled_paths:
            for cve_id, deployment_id in path[
                "cve_deployment_ids"
            ].items():
                coverage.add((
                    deployment_id,
                    cve_id,
                ))

    components = sorted({
        scenario["target_component"]
        for scenario in scenario_results
    })
    system = ebsr.aggregate_system(
        scenario_results,
        components,
    )

    component_profiles = []
    for deployment_id, attackers in system["components"].items():
        metadata = target_metadata.get(deployment_id, {})
        for attacker_id, profile in attackers.items():
            component_profiles.append({
                "deployment_id": deployment_id,
                "component_id": metadata.get("component_id"),
                "display_name": metadata.get("display_name"),
                "version": metadata.get("version"),
                "discovery_evidence": metadata.get(
                    "discovery_evidence"
                ),
                "attacker_id": attacker_id,
                "profile": profile,
            })

    not_assessed = _build_not_assessed(
        cve_assessments,
        coverage,
    )
    report = {
        "schema_version": SCHEMA_VERSION,
        "assessment_version": str(
            document.get("assessment_version") or "1.0"
        ),
        "generated_at": generated_at or _now_utc(),
        "adapter_input": document,
        "input_evidence": {
            "deployments": deepcopy(deployments_list),
            "attacker_profiles": deepcopy(attacker_profiles),
            "architecture_evidence": deepcopy(relationships),
            "cve_assessments": deepcopy(cve_assessments),
            "validation_records": deepcopy(validation_records),
            "evidence": deepcopy(evidence_items),
        },
        "propositions": propositions,
        "scenario_definitions": scenario_definitions,
        "scenario_results": scenario_results,
        "component_profiles": component_profiles,
        "system_profile": system,
        "target_profiles": target_profiles,
        "decision_trace": decision_trace,
        "not_assessed_cves": not_assessed,
        "scenario_errors": scenario_errors,
        "input_errors": deployment_errors + attacker_errors,
        "evidence_gaps": _evidence_gaps(document),
        "interpretation": {
            "quantified_values": (
                "EBSR feasibility indices are comparative, conditional "
                "technical indices and are not exploitation probabilities."
            ),
            "target_impact": (
                "Target C/I/A values come only from target-channel evidence; "
                "source CVSS impact is reported separately."
            ),
            "not_assessed": (
                "NOT_ASSESSED means evidence or scenario coverage is missing; "
                "it is not a zero-risk result."
            ),
        },
    }

    # Validate JSON compatibility before a caller can persist the report.
    json.dumps(report)
    return report


def merge_live_assessment(input_document, assessment):
    """Overlay one current deployment assessment without losing other evidence."""

    document = deepcopy(input_document or {})
    document.setdefault("schema_version", SCHEMA_VERSION)
    document.setdefault("assessment_version", "1.0")
    document.setdefault("deployments", [])
    document.setdefault("attacker_profiles", [])
    document.setdefault("architecture_evidence", [])
    document.setdefault("cve_assessments", [])
    document.setdefault("scenarios", [])
    document.setdefault("validation_records", [])

    deployment_id = assessment.get("deployment_id")
    if deployment_id:
        document["deployments"] = [
            deployment
            for deployment in document["deployments"]
            if deployment.get("deployment_id") != deployment_id
        ]
        document["deployments"].append({
            "deployment_id": deployment_id,
            "component_id": assessment.get("component_id"),
            "display_name": assessment.get("display_name"),
            "version": assessment.get("version"),
            "discovery_evidence": deepcopy(
                assessment.get("discovery_evidence")
            ),
        })

    document["cve_assessments"] = [
        record
        for record in document["cve_assessments"]
        if record.get("deployment_id") != deployment_id
    ]
    document["cve_assessments"].append(deepcopy(assessment))
    return document


def load_input(path):
    """Load a JSON evidence bundle from disk."""

    with open(path, "r", encoding="utf-8") as stream:
        document = json.load(stream)
    if not isinstance(document, dict):
        raise EBSRAdapterError(
            "The EBSR evidence file must contain a JSON object."
        )
    return document


def _version_slug(value):
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "1.0"))
    return slug.strip("-") or "1.0"


def save_assessment(report, output_path=None, output_dir=None):
    """Save a report without overwriting an existing research snapshot."""

    requested = Path(output_path) if output_path else None

    if requested is None or (
        requested.suffix.lower() != ".json"
        or requested.is_dir()
    ):
        directory = Path(
            requested
            or output_dir
            or DEFAULT_OUTPUT_DIRECTORY
        )
        stamp = datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%S%fZ"
        )
        destination = directory / (
            f"ebsr-assessment-{stamp}-"
            f"v{_version_slug(report.get('assessment_version'))}.json"
        )
    else:
        destination = requested

    destination.parent.mkdir(parents=True, exist_ok=True)

    if destination.exists():
        index = 1
        original = destination
        while destination.exists():
            destination = original.with_name(
                f"{original.stem}-{index}{original.suffix}"
            )
            index += 1

    with open(destination, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")

    return str(destination)


def load_report(path):
    """Load a previously saved EBSR report."""

    with open(path, "r", encoding="utf-8") as stream:
        report = json.load(stream)
    if (
        not isinstance(report, dict)
        or "adapter_input" not in report
    ):
        raise EBSRAdapterError(
            "The replay file is not a versioned EBSR assessment report."
        )
    return report


def replay_assessment(report_or_path, generated_at=None):
    """Re-evaluate persisted evidence without Docker or NVD access."""

    report = (
        load_report(report_or_path)
        if isinstance(report_or_path, (str, Path))
        else deepcopy(report_or_path)
    )
    replayed = build_assessment(
        report["adapter_input"],
        generated_at=generated_at or _now_utc(),
    )
    replayed["replay"] = {
        "source_schema_version": report.get("schema_version"),
        "source_generated_at": report.get("generated_at"),
    }
    return replayed


def print_assessment_summary(report):
    """Print the decision-relevant EBSR result without inventing a score."""

    print()
    print("EBSR Architecture-Aware Assessment")
    print("==================================")
    print(f"Schema version: {report['schema_version']}")
    print(f"Assessment version: {report['assessment_version']}")

    if not report["scenario_results"]:
        print("Scenario result: NOT_ASSESSED")
        print(
            "Reason: no complete, evidence-backed scenario definition "
            "was available."
        )
    else:
        for result in report["scenario_results"]:
            print()
            print(
                f"Scenario {result['scenario_id']} "
                f"(attacker {result['attacker_id']})"
            )
            print(
                f"  Target deployment: "
                f"{result['target_component']}"
            )
            print(f"  Status: {result['status']}")
            envelope = result.get("feasibility_envelope")
            print(
                "  Feasibility envelope: "
                f"{envelope if envelope is not None else 'UNQUANTIFIED'}"
            )
            print(
                "  Transition types: "
                f"{', '.join(result['transition_types'])}"
            )

    for profile in report["component_profiles"]:
        print()
        print(
            f"Component profile: {profile['deployment_id']} "
            f"/ attacker {profile['attacker_id']}"
        )
        print(f"  Status: {profile['profile']['status']}")
        print(
            "  Feasibility envelope: "
            f"{profile['profile']['feasibility_envelope']}"
        )
        print(
            "  Pareto profiles: "
            f"{len(profile['profile']['pareto_profiles'])}"
        )

    if report["not_assessed_cves"]:
        print()
        print("NOT_ASSESSED CVE records")
        print("-----------------------")
        for record in report["not_assessed_cves"]:
            print(
                f" - {record['deployment_id']} / {record['cve_id']}: "
                f"{record['reason']}"
            )

    if report["scenario_errors"]:
        print()
        print("Scenario definition errors")
        print("--------------------------")
        for error in report["scenario_errors"]:
            print(
                f" - {error.get('scenario_id')} / "
                f"{error.get('path_id', '-')}: {error['reason']}"
            )

    if report.get("input_errors"):
        print()
        print("Input identifier errors")
        print("-----------------------")
        for error in report["input_errors"]:
            print(f" - {error['reason']}")

    if report["evidence_gaps"]:
        print()
        print("Evidence gaps")
        print("-------------")
        for gap in report["evidence_gaps"]:
            print(
                f" - {gap.get('kind')}: "
                f"{gap.get('detail') or gap.get('status')}"
            )
