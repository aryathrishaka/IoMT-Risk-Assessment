"""Offline tests: baseline classification and ranking."""

import json

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


if __name__ == "__main__":
    run_all(globals())
