"""Evaluate and replay v5 offline, then compare it with v4."""

from __future__ import annotations

from datetime import datetime, timezone
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
    save_assessment,
)


V4_PATH = ROOT / "scenarios" / "ebsr_mosquitto_12546_12551_v4.json"
V5_PATH = ROOT / "scenarios" / "ebsr_mosquitto_12546_12551_v5.json"
OUTPUT_DIR = ROOT / "output" / "ebsr_assessments"
GENERATED_AT = "2026-11-16T15:16:39Z"


def propositions(report: dict) -> dict:
    return dict(report.get("propositions", {}))


def scenarios(report: dict) -> dict:
    return {
        item["scenario_id"]: item
        for item in report.get("scenario_results", [])
    }


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    v4 = build_assessment(load_input(V4_PATH), generated_at=GENERATED_AT)
    v5_document = load_input(V5_PATH)
    v5 = build_assessment(v5_document, generated_at=GENERATED_AT)
    v4_path = save_assessment(v4, output_dir=OUTPUT_DIR)
    v5_path = save_assessment(
        v5,
        output_path=OUTPUT_DIR / f"ebsr-assessment-{stamp}-v5-evaluated.json",
    )
    replay = replay_assessment(v5_path, generated_at=GENERATED_AT)
    replay_path = save_assessment(
        replay,
        output_path=OUTPUT_DIR / f"ebsr-assessment-{stamp}-v5-replayed.json",
    )

    old_props = propositions(v4)
    new_props = propositions(v5)
    proposition_changes = []
    for proposition_id in sorted(set(old_props) | set(new_props)):
        old = old_props.get(proposition_id)
        new = new_props.get(proposition_id)
        old_status = old.get("status") if old else None
        new_status = new.get("status") if new else None
        if old is None or new is None or (
            old_status != new_status
            or old.get("source") != new.get("source")
            or old.get("reason") != new.get("reason")
            or old.get("evidence") != new.get("evidence")
        ):
            proposition_changes.append(
                {
                    "proposition_id": proposition_id,
                    "change": (
                        "ADDED"
                        if old is None
                        else "REMOVED"
                        if new is None
                        else "UPDATED"
                    ),
                    "v4_status": old_status,
                    "v5_status": new_status,
                }
            )

    old_scenarios = scenarios(v4)
    new_scenarios = scenarios(v5)
    scenario_changes = []
    for scenario_id in sorted(old_scenarios):
        old = old_scenarios[scenario_id]
        new = new_scenarios[scenario_id]
        old_impacts = [path["target_impact"] for path in old["paths"]]
        new_impacts = [path["target_impact"] for path in new["paths"]]
        old_grades = [path["reproduction_grades"] for path in old["paths"]]
        new_grades = [path["reproduction_grades"] for path in new["paths"]]
        scenario_changes.append(
            {
                "scenario_id": scenario_id,
                "status_changed": old["status"] != new["status"],
                "feasibility_changed": (
                    old["feasibility_envelope"]
                    != new["feasibility_envelope"]
                ),
                "target_impact_changed": old_impacts != new_impacts,
                "reproduction_grades_changed": old_grades != new_grades,
                "path_trace_changed": old["paths"] != new["paths"],
                "v4_status": old["status"],
                "v5_status": new["status"],
                "v4_feasibility": old["feasibility_envelope"],
                "v5_feasibility": new["feasibility_envelope"],
                "target_impact": new_impacts,
                "reproduction_grades": new_grades,
            }
        )

    replay_checks = {
        "scenario_results": (
            replay["scenario_results"] == v5["scenario_results"]
        ),
        "component_profiles": (
            replay["component_profiles"] == v5["component_profiles"]
        ),
        "not_assessed_cves": (
            replay["not_assessed_cves"] == v5["not_assessed_cves"]
        ),
        "propositions": replay["propositions"] == v5["propositions"],
    }
    comparison = {
        "schema_version": "1.0",
        "generated_at": GENERATED_AT,
        "v4_scenario": str(V4_PATH.relative_to(ROOT)),
        "v5_scenario": str(V5_PATH.relative_to(ROOT)),
        "v4_report": v4_path,
        "v5_report": v5_path,
        "v5_replay": replay_path,
        "observation": v5_document["observations"][-1],
        "proposition_changes": proposition_changes,
        "scenario_changes": scenario_changes,
        "replay_checks": replay_checks,
    }
    comparison_path = (
        OUTPUT_DIR / f"ebsr-assessment-{stamp}-v5-comparison.json"
    )
    comparison_path.write_text(
        json.dumps(comparison, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"V4_REPORT={v4_path}")
    print(f"V5_REPORT={v5_path}")
    print(f"V5_REPLAY={replay_path}")
    print(f"COMPARISON={comparison_path}")
    print(f"PROPOSITION_CHANGES={len(proposition_changes)}")
    for item in proposition_changes:
        print(
            f"{item['change']} {item['proposition_id']} "
            f"{item['v4_status']}->{item['v5_status']}"
        )
    for item in scenario_changes:
        print(
            f"{item['scenario_id']} status_changed={item['status_changed']} "
            f"feasibility_changed={item['feasibility_changed']} "
            f"impact_changed={item['target_impact_changed']} "
            f"trace_changed={item['path_trace_changed']} "
            f"grades_changed={item['reproduction_grades_changed']} "
            f"status={item['v5_status']} "
            f"feasibility={item['v5_feasibility']}"
        )
    return 0 if all(replay_checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
