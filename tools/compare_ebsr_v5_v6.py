"""Evaluate and replay v6 offline, then compare it with v5."""

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


V5_PATH = ROOT / "scenarios" / "ebsr_mosquitto_12546_12551_v5.json"
V6_PATH = ROOT / "scenarios" / "ebsr_mosquitto_12546_12551_v6.json"
OUTPUT_DIR = ROOT / "output" / "ebsr_assessments"
GENERATED_AT = "2026-11-16T15:16:39Z"


def scenario_map(report: dict) -> dict:
    return {
        item["scenario_id"]: item
        for item in report.get("scenario_results", [])
    }


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    v5 = build_assessment(
        load_input(V5_PATH),
        generated_at=GENERATED_AT,
    )
    v6_document = load_input(V6_PATH)
    v6 = build_assessment(v6_document, generated_at=GENERATED_AT)
    v5_path = save_assessment(v5, output_dir=OUTPUT_DIR)
    v6_path = save_assessment(
        v6,
        output_path=OUTPUT_DIR / f"ebsr-assessment-{stamp}-v6-evaluated.json",
    )
    replay = replay_assessment(v6_path, generated_at=GENERATED_AT)
    replay_path = save_assessment(
        replay,
        output_path=OUTPUT_DIR / f"ebsr-assessment-{stamp}-v6-replayed.json",
    )

    old_props = v5.get("propositions", {})
    new_props = v6.get("propositions", {})
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
                    "v5_status": old_status,
                    "v6_status": new_status,
                }
            )

    v5_scenarios = scenario_map(v5)
    v6_scenarios = scenario_map(v6)
    scenario_changes = []
    for scenario_id in sorted(v5_scenarios):
        old = v5_scenarios[scenario_id]
        new = v6_scenarios[scenario_id]
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
                "v5_status": old["status"],
                "v6_status": new["status"],
                "v5_feasibility": old["feasibility_envelope"],
                "v6_feasibility": new["feasibility_envelope"],
                "v5_target_impact": old_impacts,
                "v6_target_impact": new_impacts,
                "v6_reproduction_grades": new_grades,
            }
        )

    replay_checks = {
        "scenario_results": replay["scenario_results"] == v6["scenario_results"],
        "component_profiles": (
            replay["component_profiles"] == v6["component_profiles"]
        ),
        "not_assessed_cves": (
            replay["not_assessed_cves"] == v6["not_assessed_cves"]
        ),
        "propositions": replay["propositions"] == v6["propositions"],
    }
    comparison = {
        "schema_version": "1.0",
        "generated_at": GENERATED_AT,
        "v5_scenario": str(V5_PATH.relative_to(ROOT)),
        "v6_scenario": str(V6_PATH.relative_to(ROOT)),
        "v5_report": v5_path,
        "v6_report": v6_path,
        "v6_replay": replay_path,
        "correction": v6_document["evidence_corrections"][-1],
        "proposition_changes": proposition_changes,
        "scenario_changes": scenario_changes,
        "replay_checks": replay_checks,
    }
    comparison_path = (
        OUTPUT_DIR / f"ebsr-assessment-{stamp}-v6-comparison.json"
    )
    comparison_path.write_text(
        json.dumps(comparison, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"V5_REPORT={v5_path}")
    print(f"V6_REPORT={v6_path}")
    print(f"V6_REPLAY={replay_path}")
    print(f"COMPARISON={comparison_path}")
    print(f"PROPOSITION_CHANGES={len(proposition_changes)}")
    for item in proposition_changes:
        print(
            f"{item['change']} {item['proposition_id']} "
            f"{item['v5_status']}->{item['v6_status']}"
        )
    for item in scenario_changes:
        print(
            f"{item['scenario_id']} status={item['v6_status']} "
            f"status_changed={item['status_changed']} "
            f"feasibility_changed={item['feasibility_changed']} "
            f"impact_changed={item['target_impact_changed']} "
            f"trace_changed={item['path_trace_changed']} "
            f"grades_changed={item['reproduction_grades_changed']} "
            f"feasibility={item['v6_feasibility']}"
        )
    return 0 if all(replay_checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
