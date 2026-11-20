"""Evaluate, replay, and compare v9 with the archived v8 assessment."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ebsr_adapter import build_assessment, load_input, replay_assessment
from run_ebsr_experiment_v8 import changed_conditions, condition_states, impact_summary, markdown_table

STEM = "ebsr-assessment-20261118T200923198752Z"
ARCHIVE = ROOT / "output/ebsr_assessments"
V9 = ROOT / "scenarios/ebsr_cve_2018_12546_experiment_v9.json"
REPLAY_FIELDS = ("scenario_results", "propositions", "component_profiles")


def assert_replay_equal(report, replay):
    for field in REPLAY_FIELDS:
        if report[field] != replay[field]:
            raise ValueError(f"Offline replay changed {field}")


def summarize_scope(result):
    return ", ".join(
        f"{item['source_observation_grade']} / {item['downstream_cve_specific_testing']}"
        for item in result["reproduction_scope"]
    ) or "No scope entry"


def compare(before, after):
    old_results = {result["scenario_id"]: result for result in before["scenario_results"]}
    rows = []
    for new in after["scenario_results"]:
        sid = new["scenario_id"]
        old = old_results[sid]
        old_states = condition_states(before, old)
        new_states = condition_states(after, new)
        rows.append({
            "before_scenario_id": sid,
            "after_scenario_id": sid,
            "condition_changes": changed_conditions(old_states, new_states),
            "before_feasibility": old["feasibility_envelope"],
            "after_feasibility": new["feasibility_envelope"],
            "before_target_impact": impact_summary(old),
            "after_target_impact": impact_summary(new),
            "before_reproduction": summarize_scope(old),
            "after_reproduction": summarize_scope(new),
            "before_reproduction_scope": old["reproduction_scope"],
            "after_reproduction_scope": new["reproduction_scope"],
        })
    return rows


def save_new(path, content):
    if path.exists():
        if path.read_bytes() != content:
            raise FileExistsError(f"Output already exists. Choose a new --out directory: {path}")
    else:
        with path.open("xb") as stream:
            stream.write(content)


def json_bytes(document):
    return (json.dumps(document, indent=2) + "\n").encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ARCHIVE)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    before_path = ARCHIVE / f"{STEM}-v8-experiment-evaluated.json"
    before = json.loads(before_path.read_text(encoding="utf-8"))
    archived_replay = json.loads(
        (ARCHIVE / f"{STEM}-v8-experiment-replayed.json").read_text(encoding="utf-8")
    )
    assert_replay_equal(before, archived_replay)
    assert_replay_equal(before, replay_assessment(before))
    # Reuse the archived assessment timestamp for deterministic comparison reports.
    generated_at = before["generated_at"]
    after = build_assessment(load_input(V9), generated_at=generated_at)
    report_path = args.out / f"{STEM}-v9-experiment-evaluated.json"
    save_new(report_path, json_bytes(after))
    replay = replay_assessment(report_path, generated_at=generated_at)
    assert_replay_equal(after, replay)
    save_new(args.out / f"{STEM}-v9-experiment-replayed.json", json_bytes(replay))

    rows = compare(before, after)
    comparison = {
        "v8_archive": before_path.relative_to(ROOT).as_posix(),
        "v9_bundle": V9.relative_to(ROOT).as_posix(),
        "v8_and_v9_offline_replay_verified": True,
        "rows": rows,
    }
    prefix = f"{STEM}-v9-experiment-comparison"
    save_new(args.out / f"{prefix}.json", json_bytes(comparison))
    markdown = (
        "# CVE-2018-12546 v8 and v9 comparison\n\n"
        + markdown_table(rows)
        + "\n\nBoth archived v8 and evaluated v9 reproduced offline. "
        "The direct control confirmed subscriber access using an authorized retained replacement. "
        "The downstream control withheld the tested event at Mosquitto, leaving Ditto and InfluxDB "
        "event-specific receiver handling unresolved. Control target integrity findings apply to the "
        "captured Thing and retained marker within each observation window. "
        "Vulnerable InfluxDB delivery was confirmed by CSV while the CVE-free step has unresolved A/G.\n"
    )
    save_new(args.out / f"{prefix}.md", markdown.encode("utf-8"))
    print(f"Verified v8 and v9 offline replay. Reports saved in {args.out.resolve()}")


if __name__ == "__main__":
    main()
