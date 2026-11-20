"""Evaluate and replay v4 offline, then compare it with frozen v3."""

from __future__ import annotations

import json
from datetime import datetime, timezone
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


V3_PATH = ROOT / "scenarios" / "ebsr_mosquitto_12546_12551_v3.json"
V4_PATH = ROOT / "scenarios" / "ebsr_mosquitto_12546_12551_v4.json"
OUTPUT_DIR = ROOT / "output" / "ebsr_assessments"
GENERATED_AT = "2026-11-15T19:42:31.648833Z"


def proposition_map(report: dict) -> dict:
    return {
        proposition_id: proposition
        for proposition_id, proposition in report.get(
            "propositions", {}
        ).items()
    }


def scenario_map(report: dict) -> dict:
    return {
        result["scenario_id"]: result
        for result in report.get("scenario_results", [])
    }


def interval_equal(left, right) -> bool:
    return left == right


def main() -> int:
    run_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    v3_report = build_assessment(
        load_input(V3_PATH),
        generated_at=GENERATED_AT,
    )
    document_v4 = load_input(V4_PATH)
    v4_report = build_assessment(document_v4, generated_at=GENERATED_AT)
    v3_path = save_assessment(v3_report, output_dir=OUTPUT_DIR)
    v4_path = save_assessment(
        v4_report,
        output_path=OUTPUT_DIR
        / f"ebsr-assessment-{run_stamp}-v4-evaluated.json",
    )
    replayed = replay_assessment(v4_path, generated_at=GENERATED_AT)
    replay_path = save_assessment(
        replayed,
        output_path=OUTPUT_DIR
        / f"ebsr-assessment-{run_stamp}-v4-replayed.json",
    )

    v3_props = proposition_map(v3_report)
    v4_props = proposition_map(v4_report)
    proposition_differences = []
    for proposition_id in sorted(set(v3_props) | set(v4_props)):
        old = v3_props.get(proposition_id)
        new = v4_props.get(proposition_id)
        old_status = old.get("status") if old else None
        new_status = new.get("status") if new else None
        old_source = old.get("source") if old else None
        new_source = new.get("source") if new else None
        old_reason = old.get("reason") if old else None
        new_reason = new.get("reason") if new else None
        if (
            old_status != new_status
            or old_source != new_source
            or old_reason != new_reason
        ):
            proposition_differences.append(
                {
                    "proposition_id": proposition_id,
                    "change": (
                        "ADDED"
                        if old is None
                        else "REMOVED"
                        if new is None
                        else "UPDATED"
                    ),
                    "v3_status": old_status,
                    "v4_status": new_status,
                    "v3_source": old_source,
                    "v4_source": new_source,
                    "v3_reason": old_reason,
                    "v4_reason": new_reason,
                }
            )

    v3_scenarios = scenario_map(v3_report)
    v4_scenarios = scenario_map(v4_report)
    scenario_differences = []
    for scenario_id in sorted(v3_scenarios):
        old = v3_scenarios[scenario_id]
        new = v4_scenarios[scenario_id]
        status_changed = old.get("status") != new.get("status")
        feasibility_changed = not interval_equal(
            old.get("feasibility_envelope"),
            new.get("feasibility_envelope"),
        )
        old_impacts = [path.get("target_impact") for path in old.get("paths", [])]
        new_impacts = [path.get("target_impact") for path in new.get("paths", [])]
        target_impact_changed = old_impacts != new_impacts
        path_trace_changed = old.get("paths") != new.get("paths")
        result_changed = (
            status_changed or feasibility_changed or target_impact_changed
        )
        scenario_differences.append(
            {
                "scenario_id": scenario_id,
                "result_changed": result_changed,
                "path_trace_changed": path_trace_changed,
                "status_changed": status_changed,
                "feasibility_changed": feasibility_changed,
                "target_impact_changed": target_impact_changed,
                "v3_status": old.get("status"),
                "v4_status": new.get("status"),
                "v3_feasibility_envelope": old.get("feasibility_envelope"),
                "v4_feasibility_envelope": new.get("feasibility_envelope"),
                "reason": (
                    "Status, feasibility and target impact are unchanged."
                    if not result_changed
                    else "At least one decision-result field changed."
                )
                + (
                    " The evidence trace changed."
                    if path_trace_changed
                    else " The evidence trace is unchanged."
                ),
            }
        )

    replay_checks = {
        "scenario_results": (
            replayed.get("scenario_results")
            == v4_report.get("scenario_results")
        ),
        "component_profiles": (
            replayed.get("component_profiles")
            == v4_report.get("component_profiles")
        ),
        "not_assessed_cves": (
            replayed.get("not_assessed_cves")
            == v4_report.get("not_assessed_cves")
        ),
        "propositions": (
            replayed.get("propositions")
            == v4_report.get("propositions")
        ),
    }

    comparison = {
        "schema_version": "1.0",
        "generated_at": GENERATED_AT,
        "v3_scenario": str(V3_PATH.relative_to(ROOT)),
        "v4_scenario": str(V4_PATH.relative_to(ROOT)),
        "v3_report": v3_path,
        "v4_report": v4_path,
        "v4_replay": replay_path,
        "observation": document_v4.get("observations", [None])[0],
        "proposition_differences": proposition_differences,
        "scenario_differences": scenario_differences,
        "replay_checks": replay_checks,
    }
    comparison_path = (
        OUTPUT_DIR
        / f"ebsr-assessment-{run_stamp}-v4-comparison.json"
    )
    comparison_path.write_text(
        json.dumps(comparison, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"V3_REPORT={v3_path}")
    print(f"V4_REPORT={v4_path}")
    print(f"V4_REPLAY={replay_path}")
    print(f"COMPARISON={comparison_path}")
    print(f"PROPOSITION_CHANGES={len(proposition_differences)}")
    for item in proposition_differences:
        print(
            f"{item['change']} {item['proposition_id']} "
            f"{item['v3_status']}->{item['v4_status']}"
        )
    print(
        "SCENARIO_RESULT_CHANGES="
        f"{sum(1 for item in scenario_differences if item['result_changed'])}"
    )
    print(
        "SCENARIO_TRACE_CHANGES="
        f"{sum(1 for item in scenario_differences if item['path_trace_changed'])}"
    )
    for item in scenario_differences:
        print(
            f"{item['scenario_id']} result_changed={item['result_changed']} "
            f"trace_changed={item['path_trace_changed']} "
            f"status={item['v4_status']} "
            f"envelope={item['v4_feasibility_envelope']}"
        )
    return 0 if all(replay_checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
