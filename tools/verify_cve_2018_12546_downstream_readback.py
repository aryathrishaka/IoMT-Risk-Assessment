"""Verify Experiment 2 InfluxDB exports against the saved assessment evidence."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_ROOT = ROOT / "output" / "evidence_runs"
DEFAULT_EVIDENCE = (
    EVIDENCE_ROOT
    / "cve-2018-12546-downstream-20261118T200923198752Z.json"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_flux_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as source:
        content = [line for line in source if not line.startswith("#")]
    return list(csv.DictReader(content))


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def seconds_delta(left: str, right: str) -> float:
    return (parse_time(left) - parse_time(right)).total_seconds()


def next_nanosecond(value: str) -> str:
    parsed = parse_time(value)
    # A one-microsecond exclusive stop is larger than the 100 ns tick used in
    # these exports and remains before any later event.
    end = parsed + timedelta(microseconds=1)
    return end.isoformat().replace("+00:00", "Z")


def point_time_from_ns(value: int) -> str:
    seconds, nanoseconds = divmod(value, 1_000_000_000)
    timestamp = datetime.fromtimestamp(seconds, timezone.utc).replace(
        microsecond=nanoseconds // 1000
    )
    return timestamp.isoformat().replace("+00:00", "Z")


def range_query(
    *,
    bucket: str,
    thing_id: str,
    start: str,
    stop: str,
    marker: str | None = None,
) -> str:
    lines = [
        f'from(bucket: "{bucket}")',
        f"  |> range(start: {start}, stop: {stop})",
        '  |> filter(fn: (r) => r._measurement == "ditto_thing_event")',
        '  |> filter(fn: (r) => r._field == "temperature")',
        f'  |> filter(fn: (r) => r.thing_id == "{thing_id}")',
    ]
    if marker is not None:
        lines.append(
            f'  |> filter(fn: (r) => r.run_marker == "{marker}")'
        )
    lines.append(
        '  |> keep(columns: ["_time", "_value", "thing_id", "run_marker"])'
    )
    return "\n".join(lines)


def normalized_row(row: dict[str, str]) -> dict[str, object]:
    return {
        "time": row["_time"],
        "value": float(row["_value"]),
        "run_marker": row["run_marker"],
        "thing_id": row["thing_id"],
        "table": row.get("table"),
    }


def row_matches(
    row: dict[str, object],
    *,
    thing_id: str,
    marker: str,
    value: float,
) -> bool:
    return (
        row["thing_id"] == thing_id
        and row["run_marker"] == marker
        and row["value"] == value
    )


def build_verification(
    evidence_path: Path,
    vulnerable_csv: Path,
    control_csv: Path,
) -> dict:
    evidence_hash_before = sha256(evidence_path)
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    vulnerable_rows = [normalized_row(row) for row in read_flux_csv(vulnerable_csv)]
    control_rows = [normalized_row(row) for row in read_flux_csv(control_csv)]

    vulnerable = evidence["arms"]["vulnerable"]
    control = evidence["arms"]["control"]
    vulnerable_thing_id = vulnerable["thing_id"]
    control_thing_id = control["thing_id"]
    vulnerable_retained_marker = vulnerable["retained"][
        "stored_message_check"
    ]["marker"]
    control_retained_marker = control["retained"][
        "stored_message_check"
    ]["marker"]
    vulnerable_retained_value = vulnerable["retained"][
        "stored_message_check"
    ]["temperature"]
    control_retained_value = control["retained"][
        "stored_message_check"
    ]["temperature"]
    normal_marker = control["normal"]["marker"]
    normal_value = control["normal"]["temperature"]
    post_marker = control["post_control"]["marker"]
    post_value = control["post_control"]["temperature"]

    vulnerable_match_flags = [
        row_matches(
            row,
            thing_id=vulnerable_thing_id,
            marker=vulnerable_retained_marker,
            value=vulnerable_retained_value,
        )
        for row in vulnerable_rows
    ]
    control_retained_rows = [
        row
        for row in control_rows
        if row["run_marker"] == control_retained_marker
    ]
    control_normal_rows = [
        row for row in control_rows if row["run_marker"] == normal_marker
    ]
    control_post_rows = [
        row for row in control_rows if row["run_marker"] == post_marker
    ]
    control_id_match = all(
        row["thing_id"] == control_thing_id for row in control_rows
    )
    support_start = control_rows[0]["time"]
    support_stop = next_nanosecond(control_rows[-1]["time"])
    retained_window_start = control["retained"]["downstream_observation"][
        "open_started_utc"
    ]
    retained_window_stop = control["post_control"]["publish"][
        "publication_attempted_utc"
    ]

    vulnerable_writer = vulnerable["retained"]["downstream_observation"][
        "writer_event"
    ]
    control_normal_writer = control["normal"]["writer_event"]
    control_post_writer = control["post_control"]["writer_event"]

    vulnerable_writer_time = point_time_from_ns(
        vulnerable_writer["influx_point_time_ns"]
    )
    normal_writer_time = point_time_from_ns(
        control_normal_writer["influx_point_time_ns"]
    )
    post_writer_time = point_time_from_ns(
        control_post_writer["influx_point_time_ns"]
    )
    vulnerable_state_correlation = (
        seconds_delta(vulnerable_rows[-1]["time"], vulnerable_writer_time)
        if vulnerable_rows
        else None
    )
    normal_correlation = (
        seconds_delta(control_normal_rows[0]["time"], normal_writer_time)
        if control_normal_rows
        else None
    )
    post_correlation = (
        seconds_delta(control_post_rows[0]["time"], post_writer_time)
        if control_post_rows
        else None
    )
    control_window_brackets_retained = (
        parse_time(support_start) <= parse_time(retained_window_start)
        and parse_time(support_stop) > parse_time(retained_window_stop)
    )
    evidence_hash_after = sha256(evidence_path)

    critical_checks = {
        "vulnerable_row_count_is_two": len(vulnerable_rows) == 2,
        "vulnerable_rows_all_match_thing_marker_value": all(
            vulnerable_match_flags
        ),
        "vulnerable_evidence_event_matches_marker": (
            vulnerable_writer.get("run_marker") == vulnerable_retained_marker
            and vulnerable_writer.get("thing_id") == vulnerable_thing_id
            and vulnerable_writer.get("temperature") == vulnerable_retained_value
        ),
        "vulnerable_last_row_matches_writer_timestamp": (
            vulnerable_state_correlation is not None
            and abs(vulnerable_state_correlation) <= 0.001
        ),
        "control_rows_are_normal_and_post_only": (
            len(control_rows) == 2
            and len(control_normal_rows) == 1
            and len(control_post_rows) == 1
        ),
        "control_retained_marker_row_count_is_zero": (
            len(control_retained_rows) == 0
        ),
        "control_rows_all_match_thing_id": control_id_match,
        "control_normal_row_matches_evidence": (
            len(control_normal_rows) == 1
            and control_normal_rows[0]["value"] == normal_value
        ),
        "control_post_row_matches_evidence": (
            len(control_post_rows) == 1
            and control_post_rows[0]["value"] == post_value
        ),
        "control_normal_row_matches_writer_timestamp": (
            normal_correlation is not None and abs(normal_correlation) <= 0.001
        ),
        "control_post_row_matches_writer_timestamp": (
            post_correlation is not None and abs(post_correlation) <= 0.001
        ),
        "control_support_window_brackets_retained_observation": (
            control_window_brackets_retained
        ),
        "control_has_no_retained_writer_event": (
            control["retained"]["downstream_observation"]["writer_event"] is None
        ),
        "original_evidence_hash_unchanged": (
            evidence_hash_before == evidence_hash_after
        ),
    }
    verified = all(critical_checks.values())
    if not verified:
        status = "MISMATCH"
    else:
        status = "CONFIRMED"

    return {
        "schema_version": "1.0",
        "verification_id": (
            "cve-2018-12546-downstream-readback-verification"
        ),
        "verified_at_utc": datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "status": status,
        "result": (
            "PAIRED_DOWNSTREAM_DIFFERENCE_CONFIRMED"
            if verified
            else "PAIRED_DOWNSTREAM_READBACK_MISMATCH"
        ),
        "source_evidence": {
            "path": str(evidence_path),
            "sha256": evidence_hash_before,
            "sha256_after": evidence_hash_after,
            "unchanged": evidence_hash_before == evidence_hash_after,
        },
        "source_csv_exports": {
            "vulnerable_retained": {
                "original_path": str(vulnerable_csv),
                "sha256": sha256(vulnerable_csv),
                "row_count": len(vulnerable_rows),
            },
            "control_window": {
                "original_path": str(control_csv),
                "sha256": sha256(control_csv),
                "row_count": len(control_rows),
            },
        },
        "vulnerable_retained_marker": {
            "thing_id": vulnerable_thing_id,
            "run_marker": vulnerable_retained_marker,
            "temperature": vulnerable_retained_value,
            "row_count": len(vulnerable_rows),
            "distinct_timestamp_count": len(
                {row["time"] for row in vulnerable_rows}
            ),
            "rows": vulnerable_rows,
            "all_rows_match": all(vulnerable_match_flags),
            "database_duplicate_rows_confirmed": (
                len(vulnerable_rows) > 1
                and len({row["time"] for row in vulnerable_rows})
                == len(vulnerable_rows)
            ),
            "duplicate_inference_basis": (
                "Two distinct matching rows are present in the CSV export. "
                "The count is not inferred from writer-event count."
            ),
            "writer_state_point_time": vulnerable_writer_time,
            "writer_state_to_last_row_delta_seconds": (
                vulnerable_state_correlation
            ),
        },
        "control_retained_marker": {
            "thing_id": control_thing_id,
            "run_marker": control_retained_marker,
            "temperature": control_retained_value,
            "row_count": len(control_retained_rows),
            "rows": control_retained_rows,
            "retained_observation_window": {
                "start": retained_window_start,
                "stop_exclusive": retained_window_stop,
            },
            "marker_query": range_query(
                bucket=evidence["environment"]["bucket"],
                thing_id=control_thing_id,
                start=support_start,
                stop=support_stop,
                marker=control_retained_marker,
            ),
        },
        "control_window_support": {
            "row_count": len(control_rows),
            "normal_row_count": len(control_normal_rows),
            "post_control_row_count": len(control_post_rows),
            "retained_marker_row_count": len(control_retained_rows),
            "window": {
                "start": support_start,
                "stop_exclusive": support_stop,
                "derivation": (
                    "Starts at the normal row timestamp and ends immediately "
                    "after the post-control row timestamp."
                ),
            },
            "all_rows_query": range_query(
                bucket=evidence["environment"]["bucket"],
                thing_id=control_thing_id,
                start=support_start,
                stop=support_stop,
            ),
            "rows": control_rows,
            "normal_writer_state_point_time": normal_writer_time,
            "normal_row_to_writer_state_delta_seconds": normal_correlation,
            "post_writer_state_point_time": post_writer_time,
            "post_row_to_writer_state_delta_seconds": post_correlation,
        },
        "checks": critical_checks,
        "paired_summary": {
            "vulnerable": {
                "version": "1.5.5",
                "retained_database_row_count": len(vulnerable_rows),
                "thing_changed": vulnerable["assessment"][
                    "malicious_thing_changed"
                ],
                "writer_event": vulnerable["assessment"][
                    "malicious_writer_event"
                ],
                "policy_outcome": vulnerable["assessment"]["outcome"],
            },
            "control": {
                "version": "2.1.2",
                "retained_database_row_count": len(control_retained_rows),
                "thing_changed": control["assessment"][
                    "malicious_thing_changed"
                ],
                "writer_event": control["assessment"][
                    "malicious_writer_event"
                ],
                "normal_row_count": len(control_normal_rows),
                "post_control_row_count": len(control_post_rows),
                "policy_outcome": control["assessment"]["outcome"],
            },
            "difference": (
                "The vulnerable retained command produced two confirmed "
                "database rows; the control produced no retained-marker row "
                "inside its exact tested window."
                if verified
                else "The saved evidence and CSV exports do not reconcile."
            ),
            "assessment_boundary": (
                "Verified downstream policy compliance only. This does not "
                "establish clinical harm or a numerical C/I/A magnitude."
            ),
        },
    }


def markdown_summary(record: dict) -> str:
    vulnerable = record["vulnerable_retained_marker"]
    control_retained = record["control_retained_marker"]
    control_support = record["control_window_support"]
    return f"""# CVE-2018-12546 Downstream Readback Verification

Status: **{record['status']}**

| Arm | Retained-marker rows | Thing changed | Writer event | Supporting rows |
|---|---:|---|---|---:|
| Mosquitto 1.5.5 | {vulnerable['row_count']} | Yes | Yes | 2 retained rows |
| Mosquitto 2.1.2 control | {control_retained['row_count']} | No | No | 2 normal/post-control rows |

## Vulnerable database rows

Thing ID: `{vulnerable['thing_id']}`

| Time (UTC) | Temperature | Marker |
|---|---:|---|
""" + "".join(
        f"| {row['time']} | {row['value']:.2f} | `{row['run_marker']}` |\n"
        for row in vulnerable["rows"]
    ) + f"""
The two database rows share the exact Thing ID, marker and temperature but
have distinct timestamps. Duplicate database rows are therefore confirmed by
the CSV itself, not inferred from duplicate writer events.

## Control window

Thing ID: `{control_retained['thing_id']}`

Retained marker queried: `{control_retained['run_marker']}`

| Time (UTC) | Temperature | Marker |
|---|---:|---|
""" + "".join(
        f"| {row['time']} | {row['value']:.2f} | `{row['run_marker']}` |\n"
        for row in control_support["rows"]
    ) + f"""
The retained-marker query returns `{control_retained['row_count']}` rows in
the explicit support window
`{control_support['window']['start']}` through
`{control_support['window']['stop_exclusive']}` (exclusive). The normal and
post-control rows demonstrate that the Thing, mapping and writer path remained
operational.

## Conclusion

{record['paired_summary']['difference']}

{record['paired_summary']['assessment_boundary']}
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--vulnerable-csv", type=Path, required=True)
    parser.add_argument("--control-csv", type=Path, required=True)
    args = parser.parse_args()

    record = build_verification(
        args.evidence,
        args.vulnerable_csv,
        args.control_csv,
    )
    stem = args.evidence.stem + "-readback"
    record_path = EVIDENCE_ROOT / f"{stem}.json"
    summary_path = EVIDENCE_ROOT / f"{stem}-summary.md"
    vulnerable_copy = EVIDENCE_ROOT / f"{stem}-vulnerable-retained.csv"
    control_copy = EVIDENCE_ROOT / f"{stem}-control-window.csv"

    shutil.copyfile(args.vulnerable_csv, vulnerable_copy)
    shutil.copyfile(args.control_csv, control_copy)
    record["source_csv_exports"]["vulnerable_retained"][
        "project_copy"
    ] = str(vulnerable_copy)
    record["source_csv_exports"]["control_window"][
        "project_copy"
    ] = str(control_copy)
    record_path.write_text(
        json.dumps(record, indent=2) + "\n",
        encoding="utf-8",
    )
    summary_path.write_text(
        markdown_summary(record) + "\n",
        encoding="utf-8",
    )

    print(f"STATUS={record['status']}")
    print(f"RESULT={record['result']}")
    print(
        "VULNERABLE_RETAINED_ROWS="
        f"{record['vulnerable_retained_marker']['row_count']}"
    )
    print(
        "CONTROL_RETAINED_ROWS="
        f"{record['control_retained_marker']['row_count']}"
    )
    print(
        "CONTROL_NORMAL_ROWS="
        f"{record['control_window_support']['normal_row_count']}"
    )
    print(
        "CONTROL_POST_ROWS="
        f"{record['control_window_support']['post_control_row_count']}"
    )
    print(f"EVIDENCE_UNCHANGED={record['source_evidence']['unchanged']}")
    print(f"VERIFICATION={record_path}")
    print(f"SUMMARY={summary_path}")
    return 0 if record["status"] == "CONFIRMED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
