"""Evaluate and replay the experiment-scoped v8 EBSR bundle offline."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ebsr_adapter import (  # noqa: E402
    build_assessment,
    load_input,
    replay_assessment,
)


V7_PATH = ROOT / "scenarios" / "ebsr_mosquitto_12546_12550_12551_v7.json"
V8_PATH = ROOT / "scenarios" / "ebsr_cve_2018_12546_experiment_v8.json"
READBACK_PATH = (
    ROOT
    / "output"
    / "evidence_runs"
    / "cve-2018-12546-downstream-20261118T200923198752Z-readback.json"
)
OUTPUT_DIR = ROOT / "output" / "ebsr_assessments"
TIMESTAMP = "20261118T200923198752Z"
GENERATED_AT = "2026-11-18T20:56:03.791759Z"


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def scenario_map(report: dict) -> dict[str, dict]:
    return {
        result["scenario_id"]: result
        for result in report["scenario_results"]
    }


def condition_states(report: dict, result: dict) -> dict:
    path = result["paths"][0]
    states = {}
    for index, transition in enumerate(path["transitions"], start=1):
        states[f"step_{index}"] = {
            variable: report["propositions"][proposition_id]["status"]
            for variable, proposition_id in transition[
                "condition_proposition_ids"
            ].items()
        }
    return states


def changed_conditions(before: dict, after: dict) -> list[str]:
    changes = []
    for step_id in sorted(set(before) | set(after)):
        before_step = before.get(step_id, {})
        after_step = after.get(step_id, {})
        for variable in ("A", "G", "H", "B", "K", "Y"):
            old = before_step.get(variable)
            new = after_step.get(variable)
            if old != new:
                changes.append(f"{step_id}.{variable}: {old or 'NEW'}->{new}")
    return changes


def impact_summary(result: dict) -> str:
    impact = result["paths"][0]["target_impact"]
    return ", ".join(
        f"{channel}={impact[channel]['status']}"
        for channel in ("C", "I", "A")
    )


def reproduction_summary(result: dict) -> str:
    grades = result["paths"][0]["reproduction_grades"]
    if not grades:
        return "CONTROL / no CVE step"
    return ", ".join(
        f"{cve_id}={grade}"
        for cve_id, grade in sorted(grades.items())
    )


def comparison_row(
    before: dict | None,
    after: dict,
    before_report: dict | None,
    after_report: dict,
) -> dict:
    before_conditions = (
        condition_states(before_report, before)
        if before is not None and before_report is not None
        else {}
    )
    after_conditions = condition_states(after_report, after)
    return {
        "before_scenario_id": (
            before["scenario_id"] if before is not None else None
        ),
        "after_scenario_id": after["scenario_id"],
        "condition_states_before": before_conditions,
        "condition_states_after": after_conditions,
        "condition_changes": changed_conditions(
            before_conditions,
            after_conditions,
        ),
        "before_status": before["status"] if before is not None else None,
        "after_status": after["status"],
        "before_feasibility": (
            before["feasibility_envelope"] if before is not None else None
        ),
        "after_feasibility": after["feasibility_envelope"],
        "before_target_impact": (
            impact_summary(before) if before is not None else None
        ),
        "after_target_impact": impact_summary(after),
        "before_reproduction": (
            reproduction_summary(before) if before is not None else None
        ),
        "after_reproduction": reproduction_summary(after),
    }


def markdown_table(rows: list[dict]) -> str:
    lines = [
        "| Comparison | Evidence-state changes | Feasibility | Target C/I/A | Reproduction scope |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        before_id = row["before_scenario_id"]
        comparison = (
            f"NEW CONTROL ({row['after_scenario_id']})"
            if before_id is None
            else f"{before_id} -> {row['after_scenario_id']}"
        )
        changes = "<br>".join(row["condition_changes"]) or "No state changes"
        feasibility = (
            f"{row['before_feasibility']} -> {row['after_feasibility']}"
            if before_id is not None
            else f"{row['after_feasibility']}"
        )
        impact = (
            f"{row['before_target_impact']} -> {row['after_target_impact']}"
            if before_id is not None
            else row["after_target_impact"]
        )
        reproduction = (
            f"{row['before_reproduction']} -> {row['after_reproduction']}"
            if before_id is not None
            else row["after_reproduction"]
        )
        lines.append(
            f"| {comparison} | {changes} | {feasibility} | "
            f"{impact} | {reproduction} |"
        )
    return "\n".join(lines)


def enrich_experiment_report(report: dict) -> dict:
    """Attach experiment-governance metadata without changing EBSR results."""

    document = report["adapter_input"]
    enriched = copy.deepcopy(report)
    for key in (
        "condition_semantics",
        "experiment_governance",
        "experiment_reproduction_scope",
        "readback_verification",
        "evidence_provenance",
        "source_hashes",
    ):
        if key in document:
            enriched[key] = copy.deepcopy(document[key])
    return enriched


def main() -> int:
    for path in (V7_PATH, V8_PATH, READBACK_PATH):
        if not path.exists():
            raise FileNotFoundError(path)

    readback = json.loads(READBACK_PATH.read_text(encoding="utf-8"))
    if readback.get("status") != "CONFIRMED":
        raise ValueError("The downstream readback is not confirmed.")

    v7_hash_before = file_hash(V7_PATH)
    v7_document = load_input(V7_PATH)
    v8_document = load_input(V8_PATH)
    v7_report = build_assessment(v7_document, generated_at=GENERATED_AT)
    v8_report = enrich_experiment_report(
        build_assessment(v8_document, generated_at=GENERATED_AT)
    )

    report_path = (
        OUTPUT_DIR
        / f"ebsr-assessment-{TIMESTAMP}-v8-experiment-evaluated.json"
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(v8_report, indent=2) + "\n",
        encoding="utf-8",
    )
    replay = enrich_experiment_report(
        replay_assessment(report_path, generated_at=GENERATED_AT)
    )
    replay_path = (
        OUTPUT_DIR
        / f"ebsr-assessment-{TIMESTAMP}-v8-experiment-replayed.json"
    )
    replay_path.write_text(
        json.dumps(replay, indent=2) + "\n",
        encoding="utf-8",
    )

    v7_scenarios = scenario_map(v7_report)
    v8_scenarios = scenario_map(v8_report)
    mappings = [
        (
            "RESEARCH-12546-MOSQUITTO",
            "EXP1-12546-VULNERABLE-MOSQUITTO",
        ),
        (
            "RESEARCH-12546-DITTO",
            "EXP2-12546-VULNERABLE-DITTO",
        ),
        (
            "RESEARCH-12546-INFLUX",
            "EXP2-12546-VULNERABLE-INFLUX",
        ),
    ]
    rows = [
        comparison_row(
            v7_scenarios[before],
            v8_scenarios[after],
            v7_report,
            v8_report,
        )
        for before, after in mappings
    ]
    rows.extend(
        comparison_row(
            None,
            v8_scenarios[scenario_id],
            None,
            v8_report,
        )
        for scenario_id in (
            "EXP1-12546-CONTROL-MOSQUITTO",
            "EXP2-12546-CONTROL-DITTO",
            "EXP2-12546-CONTROL-INFLUX",
        )
    )

    expected_checks = {
        "six_experiment_scenarios": len(v8_report["scenario_results"]) == 6,
        "no_scenario_errors": not v8_report["scenario_errors"],
        "no_input_errors": not v8_report["input_errors"],
        "vulnerable_direct_independent": (
            v8_scenarios["EXP1-12546-VULNERABLE-MOSQUITTO"][
                "paths"
            ][0]["reproduction_grades"].get("CVE-2018-12546")
            == "INDEPENDENTLY_REPRODUCED"
        ),
        "control_explicit_check_retain_source": (
            "check_retain_source true"
            in v8_document["experiment_governance"][
                "experiment_2_control_configuration"
            ]
        ),
        "vulnerable_ditto_integrity_unquantified": (
            v8_scenarios["EXP2-12546-VULNERABLE-DITTO"]["paths"][0][
                "target_impact"
            ]["I"]["status"]
            == "UNQUANTIFIED"
        ),
        "vulnerable_influx_integrity_unquantified": (
            v8_scenarios["EXP2-12546-VULNERABLE-INFLUX"]["paths"][0][
                "target_impact"
            ]["I"]["status"]
            == "UNQUANTIFIED"
        ),
        "control_retained_effect_absent": (
            v8_scenarios["EXP2-12546-CONTROL-INFLUX"]["paths"][0][
                "target_impact"
            ]["I"]["status"]
            == "F"
        ),
        "cve_free_A_unknown": (
            v8_document["evidence"]
            and next(
                item
                for item in v8_document["evidence"]
                if item["proposition_id"]
                == "unresolved.2018_12546.cve_free_step.A"
            )["status"]
            == "U"
        ),
        "cve_free_G_unknown": (
            next(
                item
                for item in v8_document["evidence"]
                if item["proposition_id"]
                == "unresolved.2018_12546.cve_free_step.G"
            )["status"]
            == "U"
        ),
        "two_database_rows_recorded": (
            v8_document["readback_verification"]["vulnerable_row_count"] == 2
        ),
        "v7_unchanged": (
            v8_document["source_hashes"]["v7_scenario"]
            == v7_hash_before
            == file_hash(V7_PATH)
        ),
        "scenario_results_replay_equal": (
            replay["scenario_results"] == v8_report["scenario_results"]
        ),
        "component_profiles_replay_equal": (
            replay["component_profiles"] == v8_report["component_profiles"]
        ),
        "propositions_replay_equal": (
            replay["propositions"] == v8_report["propositions"]
        ),
        "not_assessed_replay_equal": (
            replay["not_assessed_cves"] == v8_report["not_assessed_cves"]
        ),
        "experiment_reproduction_scope_replay_equal": (
            replay["experiment_reproduction_scope"]
            == v8_report["experiment_reproduction_scope"]
        ),
    }
    all_checks = all(expected_checks.values())

    comparison = {
        "schema_version": "1.0",
        "generated_at": GENERATED_AT,
        "experiment_scope": v8_document["assessment_scope"],
        "v7_scenario": str(V7_PATH.relative_to(ROOT)),
        "v8_scenario": str(V8_PATH.relative_to(ROOT)),
        "v8_report": str(report_path),
        "v8_replay": str(replay_path),
        "readback_verification": str(READBACK_PATH.relative_to(ROOT)),
        "rows": rows,
        "checks": expected_checks,
        "result": (
            "V8_EXPERIMENT_ASSESSMENT_VERIFIED"
            if all_checks
            else "V8_EXPERIMENT_ASSESSMENT_INVALID"
        ),
        "assessment_boundary": (
            "The new evidence is scoped to the temporary Experiment 1 and "
            "Experiment 2 deployments and windows. It is not transferred "
            "to restored baseline deployments or into EBSR mathematics."
        ),
    }
    comparison_json = (
        OUTPUT_DIR
        / f"ebsr-assessment-{TIMESTAMP}-v8-experiment-comparison.json"
    )
    comparison_md = (
        OUTPUT_DIR
        / f"ebsr-assessment-{TIMESTAMP}-v8-experiment-comparison.md"
    )
    comparison_json.write_text(
        json.dumps(comparison, indent=2) + "\n",
        encoding="utf-8",
    )
    comparison_md.write_text(
        "# CVE-2018-12546 Experiment-Scoped EBSR Comparison\n\n"
        f"Result: **{comparison['result']}**\n\n"
        f"{markdown_table(rows)}\n\n"
        f"{comparison['assessment_boundary']}\n",
        encoding="utf-8",
    )

    print(f"V8_SCENARIO={V8_PATH}")
    print(f"V8_REPORT={report_path}")
    print(f"V8_REPLAY={replay_path}")
    print(f"COMPARISON={comparison_json}")
    print(f"COMPARISON_MD={comparison_md}")
    print(f"RESULT={comparison['result']}")
    for check, passed in expected_checks.items():
        print(f"CHECK {check}={passed}")
    return 0 if all_checks else 1


if __name__ == "__main__":
    raise SystemExit(main())
