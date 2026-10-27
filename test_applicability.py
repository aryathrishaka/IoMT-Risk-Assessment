"""Offline tests: NVD configuration logic and CVSS scale policy."""

from applicability import (
    AFFECTED, NOT_AFFECTED, UNKNOWN,
    determine_applicability, cvss_summary,
)
from testutil import cpe, node, config, cve, simple, metric_entry, v2_entry, run_all

LINUX = cpe("linux_kernel", vendor="linux", part="o", vulnerable=False)
WINDOWS = cpe("windows_10", vendor="microsoft", part="o", vulnerable=False)
DEBIAN = cpe("debian_linux", vendor="debian", part="o", vulnerable=False)
MOSQ_LT_2 = cpe("mosquitto", versionEndExcluding="2.0.0")


def status(record, version="1.5.5", env=None, component="Mosquitto"):
    return determine_applicability(record, component, version, env)[0]


# ---- version matching ------------------------------------------------------

def test_inside_range():
    assert status(simple("A", cpe("mosquitto", versionEndExcluding="1.5.6"))) == AFFECTED

def test_fixed_version_outside_range():
    assert status(simple("B", cpe("mosquitto", versionEndExcluding="1.5.6")),
                  "2.1.2") == NOT_AFFECTED

def test_end_boundary_excluded():
    assert status(simple("C", cpe("mosquitto", versionEndExcluding="2.0.0")),
                  "2.0.0") == NOT_AFFECTED

def test_start_boundary_included():
    r = simple("D", cpe("mosquitto", versionStartIncluding="2.0.0",
                        versionEndExcluding="2.1.0"))
    assert status(r, "2.0.0") == AFFECTED

def test_exact_cpe_version():
    assert status(simple("E", cpe("mosquitto", version="1.5.5"))) == AFFECTED
    assert status(simple("E2", cpe("mosquitto", version="1.5.5")), "1.5.6") == NOT_AFFECTED

def test_exact_version_with_update_label_is_unknown_when_base_matches():
    r = simple("F", cpe("mosquitto", version="2.0.0", update="rc1"))
    assert status(r, "2.0.0") == UNKNOWN
    assert status(r, "1.9.0") == NOT_AFFECTED

def test_dash_version_without_range_is_unknown():
    assert status(simple("G", cpe("mosquitto", version="-"))) == UNKNOWN

def test_wildcard_without_range_is_affected():
    assert status(simple("H", cpe("mosquitto"))) == AFFECTED

def test_unparseable_detected_version_is_unknown():
    assert status(simple("I", MOSQ_LT_2), "latest") == UNKNOWN

def test_unparseable_bound_is_unknown_but_definite_failure_wins():
    unparseable = cpe("mosquitto", versionEndExcluding="not-a-version")
    assert status(simple("J", unparseable)) == UNKNOWN
    both = cpe("mosquitto", versionStartIncluding="3.0.0",
               versionEndExcluding="not-a-version")
    assert status(simple("J2", both), "1.5.5") == NOT_AFFECTED


# ---- product matching and missing data ---------------------------------------

def test_no_configurations_is_unknown():
    assert status(cve("K")) == UNKNOWN
    assert status(cve("K2", [])) == UNKNOWN

def test_other_product_not_affected():
    assert status(simple("L", cpe("mosquitto_other_thing"))) == NOT_AFFECTED

def test_substring_product_not_matched():
    r = simple("M", cpe("influxdb_enterprise", vendor="influxdata"))
    assert status(r, "2.7.11", component="InfluxDB") == NOT_AFFECTED

def test_wrong_vendor_not_matched():
    assert status(simple("N", cpe("mosquitto", vendor="someoneelse"))) == NOT_AFFECTED

def test_unconfigured_component_is_unknown():
    assert status(simple("O", MOSQ_LT_2), component="Healthcare Monitoring") == UNKNOWN

def test_unparseable_criteria_is_unknown():
    bad = {"vulnerable": True, "criteria": "not a cpe"}
    r = cve("P", [config(node(bad, MOSQ_LT_2, operator="AND"))])
    assert status(r) == UNKNOWN


# ---- platform ("running on") conditions --------------------------------------

def and_with(*conditions, target=MOSQ_LT_2):
    return cve("Q", [config(node(target), node(*conditions), operator="AND")])

def test_and_target_with_matching_platform_is_affected():
    assert status(and_with(LINUX)) == AFFECTED

def test_and_target_with_other_os_family_is_not_affected():
    assert status(and_with(WINDOWS)) == NOT_AFFECTED

def test_platform_unknown_when_environment_not_recorded():
    assert status(and_with(LINUX), env={}) == UNKNOWN

def test_same_family_different_distribution_is_unknown():
    assert status(and_with(DEBIAN)) == UNKNOWN

def test_or_inside_and_uses_any_satisfied_branch():
    assert status(and_with(WINDOWS, LINUX)) == AFFECTED


# ---- other products, negation, multiple configurations -----------------------

APP = cpe("pluginx", vendor="acme", vulnerable=False, versionEndExcluding="2.0")
ENV_APP_OLD = {"os_family": "linux", "os_cpes": [], "products": {("acme", "pluginx"): "1.0"}}
ENV_APP_NEW = {"os_family": "linux", "os_cpes": [], "products": {("acme", "pluginx"): "3.0"}}

def test_other_product_not_recorded_is_unknown():
    assert status(and_with(APP)) == UNKNOWN

def test_other_product_recorded_in_range_is_affected():
    assert status(and_with(APP), env=ENV_APP_OLD) == AFFECTED

def test_other_product_recorded_outside_range_is_not_affected():
    assert status(and_with(APP), env=ENV_APP_NEW) == NOT_AFFECTED

def negated(condition):
    return cve("R", [config(node(MOSQ_LT_2),
                            node(condition, negate=True),
                            operator="AND")])

def test_negated_node_flips_true_and_false():
    # NOT(plugin present) with plugin present -> FALSE -> not affected
    assert status(negated(APP), env=ENV_APP_OLD) == NOT_AFFECTED
    # NOT(plugin present) with plugin absent-by-version -> TRUE -> affected
    assert status(negated(APP), env=ENV_APP_NEW) == AFFECTED

def test_negated_unknown_stays_unknown():
    assert status(negated(APP)) == UNKNOWN

def test_multiple_configurations_any_true_wins():
    miss = config(node(cpe("mosquitto", versionEndExcluding="1.0")))
    hit = config(node(MOSQ_LT_2))
    assert status(cve("S", [miss, hit])) == AFFECTED

def test_multiple_configurations_unknown_beats_false():
    miss = config(node(cpe("mosquitto", versionEndExcluding="1.0")))
    unsure = config(node(MOSQ_LT_2), node(APP), operator="AND")
    assert status(cve("S2", [miss, unsure])) == UNKNOWN

def test_configuration_not_naming_target_is_ignored():
    unrelated = config(node(cpe("other", vendor="x")))
    miss = config(node(cpe("mosquitto", versionEndExcluding="1.0")))
    assert status(cve("S3", [unrelated, miss])) == NOT_AFFECTED

def test_target_only_as_platform_is_not_enough_for_affected():
    # vulnerable software is pluginx; mosquitto is just the platform
    platform = cpe("mosquitto", vulnerable=False)
    vuln_plugin = cpe("pluginx", vendor="acme", versionEndExcluding="2.0")
    r = cve("T", [config(node(vuln_plugin), node(platform), operator="AND")])
    result, reason = determine_applicability(r, "Mosquitto", "1.5.5", ENV_APP_OLD)
    assert result == UNKNOWN
    assert "platform condition" in reason


# ---- CVSS scale policy ---------------------------------------------------------

def metrics(**kw):
    return {key: val for key, val in kw.items()}

def test_primary_prefers_v31_over_v30_and_v40():
    r = cve("U", metrics=metrics(
        cvssMetricV40=[metric_entry(9.9)],
        cvssMetricV30=[metric_entry(8.0)],
        cvssMetricV31=[metric_entry(7.5)]))
    s = cvss_summary(r)
    assert s["primary"]["version"] == "3.1" and s["primary"]["score"] == 7.5

def test_primary_falls_back_to_v30():
    s = cvss_summary(cve("V", metrics=metrics(cvssMetricV30=[metric_entry(8.0)])))
    assert s["primary"]["version"] == "3.0"

def test_nvd_primary_source_preferred_over_secondary():
    r = cve("W", metrics=metrics(
        cvssMetricV31=[metric_entry(9.8, "Secondary")],
        cvssMetricV30=[metric_entry(7.5, "Primary")]))
    s = cvss_summary(r)
    assert s["primary"]["score"] == 7.5
    assert [e["score"] for e in s["other"]] == [9.8]     # retained, not dropped

def test_v40_only_has_no_primary_but_score_is_retained():
    s = cvss_summary(cve("X", metrics=metrics(cvssMetricV40=[metric_entry(9.3)])))
    assert s["primary"] is None
    assert [(e["version"], e["score"]) for e in s["other"]] == [("4.0", 9.3)]

def test_v2_only_keeps_severity_from_entry_level():
    s = cvss_summary(cve("Y", metrics=metrics(cvssMetricV2=[v2_entry(7.5, "HIGH")])))
    assert s["primary"] is None
    assert s["other"][0]["version"] == "2.0" and s["other"][0]["severity"] == "HIGH"

def test_nothing_discarded():
    r = cve("Z", metrics=metrics(
        cvssMetricV31=[metric_entry(7.5)],
        cvssMetricV40=[metric_entry(8.7)],
        cvssMetricV2=[v2_entry(6.0, "MEDIUM")]))
    s = cvss_summary(r)
    assert len(s["all"]) == 3 and len(s["other"]) == 2

def test_no_metrics():
    s = cvss_summary(cve("AA"))
    assert s["primary"] is None and s["all"] == []

def test_entry_without_score_is_not_chosen_as_primary():
    r = cve("AB", metrics=metrics(
        cvssMetricV31=[metric_entry(None)],
        cvssMetricV30=[metric_entry(6.5)]))
    assert cvss_summary(r)["primary"]["version"] == "3.0"


if __name__ == "__main__":
    run_all(globals())
