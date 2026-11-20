"""Evaluate and replay v7 offline, then compare it with v6."""

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


V6_PATH = ROOT / "scenarios" / "ebsr_mosquitto_12546_12551_v6.json"
V7_PATH = ROOT / "scenarios" / "ebsr_mosquitto_12546_12550_12551_v7.json"
OUTPUT_DIR = ROOT / "output" / "ebsr_assessments"
GENERATED_AT = "2026-11-16T19:24:00Z"


def scenario_map(report: dict) -> dict:
    return {
        item["scenario_id"]: item
        for item in report.get("scenario_results", [])
    }


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    v6 = build_assessment(
        load_input(V6_PATH),
        generated_at=GENERATED_AT,
    )
    v7_document = load_input(V7_PATH)
    v7 = build_assessment(v7_document, generated_at=GENERATED_AT)
    v6_path = save_assessment(v6, output_dir=OUTPUT_DIR)
    v7_path = save_assessment(
        v7,
        output_path=OUTPUT_DIR / f"ebsr-assessment-{stamp}-v7-evaluated.json",
    )
    replay = replay_assessment(v7_path, generated_at=GENERATED_AT)
    replay_path = save_assessment(
        replay,
        output_path=OUTPUT_DIR / f"ebsr-assessment-{stamp}-v7-replayed.json",
    )

    old_scenarios = scenario_map(v6)
    new_scenarios = scenario_map(v7)
    scenario_changes = []
    for scenario_id in sorted(set(old_scenarios) | set(new_scenarios)):
        old = old_scenarios.get(scenario_id)
        new = new_scenarios.get(scenario_id)
        if old is None or new is None:
            scenario_changes.append(
                {
                    "scenario_id": scenario_id,
                    "change": "ADDED" if old is None else "REMOVED",
                    "v6_status": old.get("status") if old else None,
                    "v7_status": new.get("status") if new else None,
                    "v7_feasibility": (
                        new.get("feasibility_envelope") if new else None
                    ),
                }
            )
            continue
        old_impacts = [path["target_impact"] for path in old["paths"]]
        new_impacts = [path["target_impact"] for path in new["paths"]]
        scenario_changes.append(
            {
                "scenario_id": scenario_id,
                "change": "UPDATED",
                "status_changed": old["status"] != new["status"],
                "feasibility_changed": (
                    old["feasibility_envelope"]
                    != new["feasibility_envelope"]
                ),
                "target_impact_changed": old_impacts != new_impacts,
                "path_trace_changed": old["paths"] != new["paths"],
                "v6_status": old["status"],
                "v7_status": new["status"],
                "v6_feasibility": old["feasibility_envelope"],
                "v7_feasibility": new["feasibility_envelope"],
            }
        )

    direct = new_scenarios["RESEARCH-12550-MOSQUITTO"]["paths"][0]
    comparison = {
        "schema_version": "1.0",
        "generated_at": GENERATED_AT,
        "v6_scenario": str(V6_PATH.relative_to(ROOT)),
        "v7_scenario": str(V7_PATH.relative_to(ROOT)),
        "v6_report": v6_path,
        "v7_report": v7_path,
        "v7_replay": replay_path,
        "new_scenario": {
            "scenario_id": "RESEARCH-12550-MOSQUITTO",
            "status": "ZERO",
            "feasibility": [0.0, 0.0],
            "target_impact": direct["target_impact"],
            "reproduction_grades": direct["reproduction_grades"],
            "condition_proposition_ids": direct["transitions"][0][
                "condition_proposition_ids"
            ],
        },
        "scenario_changes": scenario_changes,
        "replay_checks": {
            "scenario_results": (
                replay["scenario_results"] == v7["scenario_results"]
            ),
            "component_profiles": (
                replay["component_profiles"] == v7["component_profiles"]
            ),
            "not_assessed_cves": (
                replay["not_assessed_cves"] == v7["not_assessed_cves"]
            ),
            "propositions": replay["propositions"] == v7["propositions"],
        },
    }
    comparison_path = (
        OUTPUT_DIR / f"ebsr-assessment-{stamp}-v7-comparison.json"
    )
    comparison_path.write_text(
        json.dumps(comparison, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"V6_REPORT={v6_path}")
    print(f"V7_REPORT={v7_path}")
    print(f"V7_REPLAY={replay_path}")
    print(f"COMPARISON={comparison_path}")
    for item in scenario_changes:
        print(json.dumps(item, sort_keys=True))
    return 0 if all(comparison["replay_checks"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
