"""Offline tests: baseline classification and ranking."""

import json
import os
import sys
import tempfile
from unittest.mock import patch

import baseline
from baseline import build_component_baseline
from testutil import cpe, cve, simple, config, node, metric_entry, v2_entry, run_all

AFFECTS_ALL = cpe("mosquitto", versionEndExcluding="3.0")


def ids(rows):
    return [r["cve_id"] for r in rows]


def sample():
    return [
        simple("LOW", AFFECTS_ALL, metrics={"cvssMetricV31": [metric_entry(3.1)]}),
        simple("HIGH", AFFECTS_ALL, metrics={"cvssMetricV31": [metric_entry(9.8)]}),
        simple("MID30", AFFECTS_ALL, metrics={"cvssMetricV30": [metric_entry(6.5)]}),
        simple("V4ONLY", AFFECTS_ALL, metrics={"cvssMetricV40": [metric_entry(10.0)]}),
        simple("V2ONLY", AFFECTS_ALL, metrics={"cvssMetricV2": [v2_entry(9.3)]}),
        simple("NOSCORE", AFFECTS_ALL),
        simple("FIXED", cpe("mosquitto", versionEndExcluding="1.0"),
               metrics={"cvssMetricV31": [metric_entry(10.0)]}),
        cve("UNANALYSED", metrics={"cvssMetricV31": [metric_entry(8.0)]}),
    ]


def test_ranking_uses_primary_scale_only():
    result = build_component_baseline("Mosquitto", "2.1.2", sample())
    # v3.0 and v3.1 share the primary scale; v4-only / v2-only are not mixed in
    assert ids(result["affected"]) == ["HIGH", "MID30", "LOW"]


def test_other_scale_cves_are_kept_in_separate_group():
    result = build_component_baseline("Mosquitto", "2.1.2", sample())
    assert ids(result["affected_other_scale"]) == ["V4ONLY", "V2ONLY", "NOSCORE"]
    v4 = result["affected_other_scale"][0]["cvss"]["other"][0]
    assert (v4["version"], v4["score"]) == ("4.0", 10.0)      # score retained


def test_unknown_is_separate_and_not_ranked_with_affected():
    result = build_component_baseline("Mosquitto", "2.1.2", sample())
    assert ids(result["unknown"]) == ["UNANALYSED"]
    assert "UNANALYSED" not in ids(result["affected"])


def test_not_affected_is_counted():
    assert build_component_baseline("Mosquitto", "2.1.2", sample())["not_affected_count"] == 1


def test_every_candidate_is_accounted_for():
    candidates = sample()
    r = build_component_baseline("Mosquitto", "2.1.2", candidates)
    total = (len(r["affected"]) + len(r["affected_other_scale"])
             + len(r["unknown"]) + r["not_affected_count"])
    assert total == len(candidates)


def test_result_is_json_serialisable_and_names_scale():
    r = build_component_baseline("Mosquitto", "2.1.2", sample())
    json.dumps(r)
    assert r["primary_scale"] == "CVSS v3.x"


def test_unknown_version_gives_unknown_not_affected():
    r = build_component_baseline("Mosquitto", "latest", sample())
    assert r["affected"] == [] and r["affected_other_scale"] == []
    # nothing can be compared with "latest", so no CVE may be called
    # affected OR excluded: every candidate stays UNKNOWN
    assert len(r["unknown"]) == len(sample())
    assert r["not_affected_count"] == 0


def test_equal_scores_are_ordered_deterministically():
    cands = [
        simple("B", AFFECTS_ALL, metrics={"cvssMetricV31": [metric_entry(7.5)]}),
        simple("A", AFFECTS_ALL, metrics={"cvssMetricV31": [metric_entry(7.5)]}),
    ]
    assert ids(build_component_baseline("Mosquitto", "2.1.2", cands)["affected"]) == ["A", "B"]


def test_not_affected_rows_retain_applicability_provenance():
    result = build_component_baseline(
        "Mosquitto",
        "2.1.2",
        sample()
    )

    assert len(result["not_affected"]) == 1
    row = result["not_affected"][0]
    assert row["cve_id"] == "FIXED"
    assert row["applicability"]["status"] == "NOT_AFFECTED"
    assert row["applicability"]["configurations"]


def test_component_baseline_keeps_deployments_separate():
    first = build_component_baseline(
        "Mosquitto [vulnerable]",
        "1.5.5",
        sample(),
        component_id="mosquitto",
        discovery_evidence={"deployment_id": "vulnerable"}
    )
    second = build_component_baseline(
        "Mosquitto [control]",
        "2.1.2",
        sample(),
        component_id="mosquitto",
        discovery_evidence={"deployment_id": "control"}
    )

    assert first["component_id"] == second["component_id"] == "mosquitto"
    assert first["deployment_id"] == "vulnerable"
    assert second["deployment_id"] == "control"
    assert first["version"] == "1.5.5"
    assert second["version"] == "2.1.2"


def test_retrieval_status_is_serialised_without_becoming_zero_results():
    result = build_component_baseline(
        "Mosquitto",
        "1.5.5",
        [],
        component_id="mosquitto",
        retrieval={
            "status": "FAILED",
            "received": 0,
            "total_results": None,
            "error": "transport failed"
        },
        discovery_evidence={"image_digest": "sha256:abc"}
    )

    encoded = json.loads(json.dumps(result))

    assert encoded["retrieval"]["status"] == "FAILED"
    assert encoded["retrieval"]["error"] == "transport failed"
    assert encoded["retrieval_complete"] is False
    assert encoded["assessment_performed"] is False
    assert (
        encoded["no_confirmed_affected_in_retrieved_candidates"]
        is None
    )
    assert encoded["discovery_evidence"]["image_digest"] == "sha256:abc"
    assert encoded["candidates"] == 0


def test_all_retrieval_statuses_are_preserved():
    for status in ("COMPLETE", "PARTIAL", "FAILED", "MALFORMED"):
        result = build_component_baseline(
            "Mosquitto",
            "1.5.5",
            [],
            component_id="mosquitto",
            retrieval={
                "status": status,
                "received": 0,
                "total_results": 0 if status == "COMPLETE" else None,
                "error": None if status == "COMPLETE" else status.lower()
            }
        )
        encoded = json.loads(json.dumps(result))

        assert encoded["retrieval"]["status"] == status
        assert encoded["candidates"] == 0
        assert encoded["retrieval_complete"] == (status == "COMPLETE")
        assert encoded["assessment_performed"] == (
            status not in ("FAILED", "MALFORMED")
        )
        assert encoded[
            "no_confirmed_affected_in_retrieved_candidates"
        ] == (True if status == "COMPLETE" else None)


def test_no_confirmed_affected_is_false_when_an_affected_cve_exists():
    result = build_component_baseline(
        "Mosquitto",
        "1.5.5",
        sample(),
        component_id="mosquitto",
        retrieval={
            "status": "COMPLETE",
            "received": len(sample()),
            "total_results": len(sample()),
            "error": None
        }
    )

    assert result["retrieval_complete"] is True
    assert (
        result["no_confirmed_affected_in_retrieved_candidates"]
        is False
    )


def test_unknown_only_is_not_misreported_as_general_absence():
    result = build_component_baseline(
        "Mosquitto",
        "1.5.5",
        [cve("CVE-UNKNOWN")],
        component_id="mosquitto",
        retrieval={
            "status": "COMPLETE",
            "received": 1,
            "total_results": 1,
            "error": None
        }
    )

    assert len(result["unknown"]) == 1
    assert result["unknown_count"] == 1
    assert result["retrieval_complete"] is True
    assert (
        result["no_confirmed_affected_in_retrieved_candidates"]
        is True
    )


def test_manual_override_preserves_detected_version_and_evidence():
    discovery = {
        "version": "1.5.5",
        "version_source": "runtime_probe",
        "image": "efrecon/mosquitto:1.5.5",
        "image_digest": "sha256:runtime",
        "runtime_probe": {
            "status": "DETECTED",
            "version": "1.5.5"
        }
    }
    result = build_component_baseline(
        "Mosquitto [vulnerable]",
        "2.1.2",
        sample(),
        component_id="mosquitto",
        discovery_evidence=discovery,
        assessment_version_source="manual_override"
    )

    assert result["version"] == "2.1.2"
    assert result["detected_version"] == "1.5.5"
    assert result["version_override"] is True
    assert result["assessment_version_source"] == "manual_override"
    assert result["discovery_evidence"]["version"] == "1.5.5"
    assert result["discovery_evidence"]["version_source"] == "runtime_probe"
    assert result["discovery_evidence"]["image_digest"] == "sha256:runtime"


def test_baseline_main_preserves_multiple_deployments_and_statuses():
    detected = {
        "Mosquitto [vulnerable]": {
            "component_id": "mosquitto",
            "display_name": "Mosquitto",
            "architecture_component": "Mosquitto",
            "deployment_id": "vulnerable",
            "version": "1.5.5",
            "status": "Detected",
            "nvd_search_term": "mosquitto",
            "image": "eclipse-mosquitto:1.5.5",
            "image_digest": "sha256:vulnerable",
            "diagnostic": False
        },
        "Mosquitto [control]": {
            "component_id": "mosquitto",
            "display_name": "Mosquitto",
            "architecture_component": "Mosquitto",
            "deployment_id": "control",
            "version": "2.1.2",
            "status": "Detected",
            "nvd_search_term": "mosquitto",
            "image": "eclipse-mosquitto:2.1.2",
            "image_digest": "sha256:control",
            "diagnostic": False
        },
        "Unclassified deployment [lab]": {
            "status": "UNCLASSIFIED",
            "diagnostic": True,
            "reason": "No product evidence.",
            "component_id": None,
            "deployment_id": "lab"
        }
    }
    complete = {
        "status": "COMPLETE",
        "items": [],
        "received": 0,
        "total_results": 0,
        "error": None
    }
    failed = {
        "status": "FAILED",
        "items": [],
        "received": 0,
        "total_results": None,
        "error": "transport failed"
    }

    with tempfile.TemporaryDirectory() as temp_dir:
        output_path = os.path.join(temp_dir, "baseline.json")

        with patch(
            "version_detector.detect_versions",
            return_value=detected
        ):
            with patch(
                "nvd_api.search_cves_by_keyword_with_status",
                side_effect=[complete, failed]
            ):
                with patch.object(
                    sys,
                    "argv",
                    ["baseline.py", "--out", output_path]
                ):
                    baseline.main()

        with open(output_path, encoding="utf-8") as output_file:
            saved = json.load(output_file)

    assessed = {
        row["component"]: row
        for row in saved
        if row["component"].startswith("Mosquitto")
    }
    diagnostics = [
        row for row in saved if row.get("status") == "SKIPPED"
    ]

    assert assessed["Mosquitto [vulnerable]"]["deployment_id"] == "vulnerable"
    assert assessed["Mosquitto [control]"]["version"] == "2.1.2"
    assert (
        assessed["Mosquitto [vulnerable]"]["retrieval"]["status"]
        == "COMPLETE"
    )
    assert (
        assessed["Mosquitto [control]"]["retrieval"]["status"]
        == "FAILED"
    )
    assert diagnostics and diagnostics[0]["discovery_evidence"]["reason"] == "No product evidence."


if __name__ == "__main__":
    run_all(globals())
