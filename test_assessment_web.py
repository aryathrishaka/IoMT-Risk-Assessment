"""HTTP integration tests for the local assessment app with mocked upstreams."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from threading import Event, Thread
from time import monotonic, sleep
from uuid import uuid4

import pytest
import requests

from assessment_web import __main__ as web, service
from testutil import cpe, cve, metric_entry, simple


def deployment(name, version):
    return {
        "component_id": "mosquitto", "display_name": "Mosquitto",
        "deployment_id": name, "version": version, "status": "Detected",
        "version_source": "runtime_probe", "container": name,
        "nvd_search_term": "mosquitto", "container_ids": [name + "-container"],
        "raw_config": {"password": "DO-NOT-EXPOSE"},
    }


def component_deployment(name, version, component_id, product, search_term):
    return {
        "component_id": component_id, "display_name": product, "architecture_component": product,
        "deployment_id": name, "product": product, "version": version, "status": "Detected",
        "version_source": "image_metadata", "container": name, "nvd_search_term": search_term,
        "container_ids": [name + "-container"], "architecture_metadata": [],
    }


@pytest.fixture
def app(monkeypatch, tmp_path):
    monkeypatch.setattr(web, "REPORTS", tmp_path / "reports")
    with web.AppServer(("127.0.0.1", 0)) as server:
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        client = requests.Session()
        client.trust_env = False
        client.headers["X-Assessment-Session"] = uuid4().hex
        root = f"http://127.0.0.1:{server.server_port}"

        def call(path, body=None):
            return client.request("GET" if body is None else "POST", root + path, json=body, timeout=5)

        yield call
        server.shutdown()
        worker.join(timeout=5)


def wait(app):
    until = monotonic() + 5
    while monotonic() < until:
        result = app("/api/session").json()
        if result["job"]["state"] != "running":
            assert result["job"]["state"] == "finished", result["job"]
            return result
        sleep(0.015)
    pytest.fail("Assessment job did not finish")


def retrieval(status, items, count=None):
    return {"status": status, "items": items, "received": len(items), "total_results": count}


def test_discovery_assessment_saved_scenario_and_export(app, monkeypatch):
    seen = Event()
    finish = Event()
    calls = []
    monkeypatch.setattr(service, "detect_versions", lambda: {
        "old": deployment("old", "1.5.5"), "control": deployment("control", "2.1.2"),
        "unknown": {"deployment_id": "other", "status": "UNCLASSIFIED", "diagnostic": True},
    })
    affected = simple(
        "CVE-2018-12546", cpe("mosquitto", versionEndIncluding="1.5.5"),
        metrics={"cvssMetricV31": [metric_entry(6.5)]},
    )
    affected["cve"]["references"] = [
        {"url": "https://example.org/advisory"}, {"url": "javascript:alert(1)"},
    ]
    def nvd(keyword, results_per_page):
        calls.append(keyword)
        seen.set()
        assert finish.wait(5)
        return retrieval("COMPLETE", [affected, cve("CVE-2024-10525")], 2)
    monkeypatch.setattr(service, "search_cves_by_keyword_with_status", nvd)

    home = app("/").text
    assert "RiskScope" in home and "WORKSPACE" not in home
    assert all(link in home for link in ('href="#assessments"', 'href="#architecture"', 'href="#reports"'))
    assert app("/api/reports").json() == {"reports": []}
    assert app("/api/session").json()["discovery"] is None
    assert calls == []
    assert app("/api/discovery", {}).ok
    discovery = wait(app)["discovery"]
    assert {row["version"] for row in discovery["supported"]} == {"1.5.5", "2.1.2"}
    assert discovery["other"][0]["status"] == "UNCLASSIFIED"
    assert "DO-NOT-EXPOSE" not in str(discovery)
    assert app("/api/assessment", {"deployment_id": "other"}).status_code == 400
    assert app("/api/assessment", {"deployment_id": "old"}).ok
    assert seen.wait(5)
    try:
        assert app("/api/assessment", {"deployment_id": "old"}).status_code == 400
        assert app("/api/session").json()["job"]["message"] == "Retrieving NVD candidates"
    finally:
        finish.set()
    baseline = wait(app)["assessment"]
    assert calls == ["mosquitto"]
    rows = {row["cve_id"]: row for row in baseline["rows"]}
    assert rows["CVE-2018-12546"]["status"] == "AFFECTED"
    assert rows["CVE-2018-12546"]["cvss"]["primary"]["version"] == "3.1"
    assert rows["CVE-2018-12546"]["references"] == ["https://example.org/advisory"]
    assert rows["CVE-2024-10525"]["status"] == "UNKNOWN"
    cve_id = "CVE-2018-12546"
    coverage = app("/api/coverage?cve=" + cve_id).json()
    assert coverage["coverage"] == "related" and not coverage["compatible"]
    assert {item["context"] for item in coverage["related"]} == {"historical", "experiment"}
    assert all(item["target"] and item["sources"] and item["scope"] for item in coverage["related"])
    assert app("/api/evaluate", {
        "context": "live", "cve": cve_id, "scenario_id": "EXP2-12546-VULNERABLE-DITTO",
    }).status_code == 400
    absent = app("/api/coverage?cve=CVE-2024-10525").json()
    assert absent["coverage"] == "none" and absent["related"] == []
    saved = app("/api/save", {"context": "live", "cve": "CVE-2024-10525"}).json()
    downloaded = app("/reports/" + saved["report_id"] + ".json").json()
    assert downloaded["vulnerability_assessment"] == baseline
    live = downloaded["scenario_evaluation"]
    assert live["status"] == "NOT_ASSESSED" and live["coverage"] == "none"
    assert live["cve"] == "CVE-2024-10525" and live["missing_evidence"]

    historical = app("/api/historical").json()
    candidates = [entry for entry in historical["scenarios"] if cve_id in entry["cves"]]
    assert candidates
    assert candidates[0]["attacker"]["description"]
    result = app("/api/evaluate", {
        "context": "historical", "scenario_id": candidates[0]["scenario_id"],
    }).json()
    assert set(result["paths"][0]["transitions"][0]["conditions"]) == set("AGHBKY")
    assert app("/api/session").json()["assessment"] == baseline
    assert "live" not in app("/api/session").json()["results"]

    first = app("/api/save", {"context": "historical"}).json()
    second = app("/api/save", {"context": "historical"}).json()
    assert first == second
    report = app("/reports/" + first["report_id"] + ".json")
    assert report.json()["scenario_evaluation"]["provenance"]["sha256"]
    assert report.json()["vulnerability_assessment"] is None
    html = app("/reports/" + first["report_id"] + ".html")
    assert "attachment" in html.headers["Content-Disposition"]
    assert "RiskScope" in html.text and "Feasibility bounds" in html.text
    assert "Content-Disposition" not in app("/reports/" + first["report_id"] + ".html?view=1").headers
    records = app("/api/reports").json()["reports"]
    assert len(records) == 3  # Original scan, selected live CVE and historical evaluation
    assert {first["report_id"], saved["report_id"]} <= {row["report_id"] for row in records}
    assert records[0]["scope"] == "Saved historical evidence" and records[0]["version"] == "1.5.5"
    assert records[-1]["status"] == "NOT_ASSESSED" and records[-1]["retrieval"] == "COMPLETE"


@pytest.mark.parametrize("status", ["PARTIAL", "FAILED"])
def test_retrieval_outcomes_do_not_fall_back(app, monkeypatch, status):
    monkeypatch.setattr(service, "detect_versions", lambda: {"control": deployment("control", "2.1.2")})
    candidate = cve("CVE-2099-12345")
    monkeypatch.setattr(service, "search_cves_by_keyword_with_status",
                        lambda *args, **kwargs: retrieval(status, [candidate] if status == "PARTIAL" else [], 7))
    assert app("/api/discovery", {}).ok
    wait(app)
    assert app("/api/assessment", {"deployment_id": "control"}).ok
    result = wait(app)["assessment"]
    assert result["context"] == "live"
    assert result["retrieval"]["status"] == status
    assert len(result["rows"]) == (1 if status == "PARTIAL" else 0)


def test_docker_unavailable(app, monkeypatch):
    monkeypatch.setattr(service, "detect_versions", lambda: {"Docker": {"status": "DOCKER_UNAVAILABLE"}})
    assert app("/api/discovery", {}).ok
    assert wait(app)["discovery"]["status"] == "DOCKER_UNAVAILABLE"
    assert app("/api/assessment", {"deployment_id": "old"}).status_code == 400


def test_real_saved_experiments_and_source_projection(app):
    catalog = app("/api/experiment").json()
    choice = next(item for item in catalog["scenarios"] if item["scenario_id"] == "EXP2-12546-VULNERABLE-INFLUX")
    assert choice["windows"]
    assert app("/api/evaluate", {"context": "historical", "scenario_id": choice["scenario_id"]}).status_code == 400
    result = app("/api/evaluate", {"context": "experiment", "scenario_id": choice["scenario_id"]}).json()
    assert result["feasibility_envelope"] == [0, 0.7294117647058823]
    assert result["paths"][0]["target_impact"]["I"]["status"] == "UNQUANTIFIED"
    evidence = app("/api/evidence").json()
    assert len(evidence["runs"]) == 2
    assert evidence["runs"][0]["arms"]["control"]["source_check"] == "true"
    assert evidence["runs"][1]["arms"]["control"]["records"] == 0
    assert len(evidence["runs"][1]["arms"]["vulnerable"]["rows"]) == 2
    source = app("/evidence-source/run1.json").json()
    assert source == evidence["runs"][0]
    assert "configuration" not in str(source)
    assert app("/api/session").json()["results"]["experiment"] == result


@pytest.mark.parametrize("content", [None, "{incorrect"])
def test_missing_or_malformed_saved_artifact(app, monkeypatch, tmp_path, content):
    monkeypatch.setattr(service, "ROOT", tmp_path)
    path = Path(service.BUNDLES["historical"])
    (tmp_path / path.parent).mkdir()
    if content is not None:
        (tmp_path / path).write_text(content, encoding="utf-8")
    response = app("/api/historical")
    assert response.status_code == 400
    assert "missing or malformed" in response.json()["error"]


def start_assessment(app, monkeypatch, name="old"):
    monkeypatch.setattr(service, "detect_versions", lambda: {"broker": deployment(name, "1.5.5")})
    item = simple("CVE-2018-12546", cpe("mosquitto"),
                  metrics={"cvssMetricV31": [metric_entry(6.5)]})
    monkeypatch.setattr(service, "search_cves_by_keyword_with_status",
                        lambda *args, **kwargs: retrieval("COMPLETE", [item], 1))
    assert app("/api/discovery", {}).ok
    wait(app)
    assert app("/api/assessment", {"deployment_id": name}).ok
    wait(app)


def test_compatible_live_evidence_requires_matching_runtime_ids(app, monkeypatch, tmp_path):
    start_assessment(app, monkeypatch)
    monkeypatch.setattr(service, "ROOT", tmp_path)
    path = tmp_path / service.LIVE_BUNDLE
    path.parent.mkdir()
    now = datetime.now(timezone.utc)
    document = {
        "assessment_context": "live", "assessment_version": "live-validation-fixture",
        "live_evidence": {
            "observed_at_utc": (now - timedelta(minutes=1)).isoformat(),
            "valid_until_utc": (now + timedelta(minutes=5)).isoformat(),
            "container_ids_by_deployment": {"old": ["old-container"]},
        },
        "deployments": [{"deployment_id": "old", "component_id": "mosquitto", "version": "1.5.5"}],
        "attacker_profiles": [{"attacker_id": "actor", "description": "Recorded actor"}],
        "cve_assessments": [],
        "scenarios": [{"scenario_id": "bound", "attacker_id": "actor", "target_deployment_id": "old",
                       "paths": [{"path_id": "direct", "target_deployment_id": "old",
                                  "transitions": [{"step_id": "local", "source_deployment_id": "old",
                                                   "target_deployment_id": "old", "transition_type": "DIRECT",
                                                   "cve_ids": ["CVE-2018-12546"],
                                                   "conditions": {key: "U" for key in "AGHBKY"}}]}]}],
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    params = {"context": "live", "cve": "CVE-2018-12546", "scenario_id": "bound"}
    coverage = app("/api/coverage?cve=CVE-2018-12546").json()
    assert coverage["coverage"] == "compatible"
    result = app("/api/evaluate", params)
    assert result.ok, result.text
    assert result.json()["scenario_id"] == "bound" and result.json()["context"] == "live"
    saved = app("/api/save", {"context": "live", "cve": params["cve"]}).json()
    report = app("/reports/" + saved["report_id"] + ".json").json()
    assert report["scenario_evaluation"] == result.json()
    document["live_evidence"]["container_ids_by_deployment"]["old"] = ["different-container"]
    path.write_text(json.dumps(document), encoding="utf-8")
    assert app("/api/evaluate", params).status_code == 400


def test_coverage_reports_corrupt_bundle_and_rejects_experiment_collision(app, monkeypatch, tmp_path):
    original, _ = service.artifact(service.BUNDLES["experiment"])
    scenario = original["scenarios"][0]
    name = scenario["target_deployment_id"]
    start_assessment(app, monkeypatch, name)
    assert app("/api/evaluate", {"context": "live", "cve": "CVE-2018-12546",
                                "scenario_id": scenario["scenario_id"]}).status_code == 400
    monkeypatch.setattr(service, "ROOT", tmp_path)
    path = tmp_path / service.LIVE_BUNDLE
    path.parent.mkdir()
    path.write_text("{invalid", encoding="utf-8")
    info = app("/api/coverage?cve=CVE-2018-12546").json()
    assert info["coverage"] == "unavailable"
    assert any("missing or malformed" in item["message"] for item in info["errors"])
    original["assessment_context"] = "live"
    path.write_text(json.dumps(original), encoding="utf-8")
    info = app("/api/coverage?cve=CVE-2018-12546").json()
    assert info["coverage"] == "unavailable"
    assert any("explicitly scoped live evidence" in item["message"] for item in info["errors"])


def test_report_archive_isolation_and_unreadable_entries(app, tmp_path):
    bad = tmp_path / "broken-baseline.json"
    bad.write_text("{", encoding="utf-8")
    good = tmp_path / "example-baseline.json"
    good.write_text(json.dumps([dict(component="Mosquitto", version="2.1.2", candidates=0,
                                    retrieval=dict(status="COMPLETE", recorded_at_utc="2026-01-12"),
                                    raw_config=dict(password="TEST_SECRET"))]), encoding="utf-8")
    index = app("/api/reports").json()
    assert any(bad.name in issue for issue in index["issues"])
    row, = index["reports"]
    assert (row["context"], row["saved_at_utc"]) == ("historical", "2026-01-12")
    url = "/reports/" + row["report_id"]
    assert good.name in app(url + ".html?view=1").text
    assert "TEST_SECRET" not in app(url + ".json").text
    good.write_text("{}", encoding="utf-8")
    assert app(url + ".html").status_code == 422


def test_duplicate_listener_rejected():
    with web.AppServer(("127.0.0.1", 0)) as server:
        with pytest.raises(OSError):
            web.AppServer(server.server_address)


def test_architecture_profiles_match_frozen_v9_and_export_in_isolation(app):
    data = app("/api/architecture-risk", {}).json()
    expected = 0.7294117647058823
    for name, targets in data["profiles"].items():
        for target, profile in targets.items():
            interval = [0, 0] if name == "control" else [0 if target == "influxdb" else expected, expected]
            assert profile["feasibility_envelope"] == interval
            assert profile["context"] == "experiment"
    profile = data["profiles"]["vulnerable"]["influxdb"]
    assert profile["paths"][0]["target_impact"]["I"]["status"] == "UNQUANTIFIED"
    assert app("/api/session").json()["results"] == {}
    request = {"architecture_scenario": profile["scenario_id"], "context": "experiment"}
    saved = app("/api/save", request).json()
    report = app("/reports/" + saved["report_id"] + ".json").json()
    assert report["scenario_evaluation"] == profile
    assert report["vulnerability_assessment"] is None
    assert report["scenario_evaluation"]["provenance"]["sha256"] == data["provenance"]["sha256"]
    assert app("/api/save", {**request, "context":"live"}).status_code == 400


def test_architecture_missing_bundle_is_recoverable(app, monkeypatch):
    monkeypatch.setitem(service.BUNDLES, "experiment", "scenarios/missing-study.json")
    response = app("/api/architecture-risk", {})
    assert response.status_code == 400
    assert "missing-study.json" in response.json()["error"]
    assert "profiles" not in response.json()


def test_architecture_refuses_unknown_readback_count(app, monkeypatch):
    evidence = service.experimental_evidence()
    evidence["runs"][1]["arms"]["control"]["records"] = None
    monkeypatch.setattr(service, "experimental_evidence", lambda source: evidence)
    response = app("/api/architecture-risk", {})
    assert response.status_code == 400
    assert "readback count" in response.json()["error"]


def test_repeated_offline_visits_reuse_report_and_keep_technical_appendix(app):
    req = {"context": "experiment", "architecture_scenario": "EXP2-12546-VULNERABLE-INFLUX"}
    assert app("/api/architecture-risk", {}).ok
    first = app("/api/save", req).json()
    assert app("/api/architecture-risk", {}).ok
    assert app("/api/save", req).json() == first
    html = app("/reports/" + first["report_id"] + ".html?view=1").text
    assert html.index("Architecture-level risk findings") < html.index("Technical appendix")
    assert "CSV readback" in html and "Feasibility bounds" in html
    assert len(app("/api/reports").json()["reports"]) == 1


def test_generated_architecture_journey(app, monkeypatch, tmp_path):
    from ebsr_adapter import build_assessment
    broker = deployment("broker-one","1.5.5")
    broker["architecture_metadata"] = [{"networks":{"lab":["mqtt"]},"endpoint_hosts":{}}]
    ditto = {**deployment("ditto-one","3.9.7"), "component_id":"ditto","architecture_component":"Eclipse Ditto",
             "architecture_metadata":[{"networks":{"lab":["ditto"]},"endpoint_hosts":{"MQTT_HOST":"mqtt"}}]}
    database = {**deployment("db","2.7.11"), "component_id":"influxdb","architecture_component":"InfluxDB",
                "architecture_metadata":[{"networks":{"lab":["db"]},"endpoint_hosts":{}}]}
    inventory = {"broker":broker, "ditto":ditto, "db":database}
    monkeypatch.setattr(service, "detect_versions", lambda: inventory)
    candidate = simple("CVE-2018-12546", cpe("mosquitto"), metrics={"cvssMetricV31":[metric_entry(6.5, vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N")]})
    monkeypatch.setattr(service, "search_cves_by_keyword_with_status",
                        lambda *args, **kw: retrieval("COMPLETE", [candidate, cve("CVE-2099-0001")], 2))
    assert app("/api/discovery", {}).ok
    wait(app)
    assert app("/api/assessment", {"deployment_id":"broker-one"}).ok
    scan = wait(app)["assessment"]
    req = dict(deployment_id="broker-one", captured_at=scan["captured_at"], cve="CVE-2018-12546")
    def analyze(**extra):
        return app("/api/analyze",{**req, **extra})
    direct = analyze().json()
    assert direct["result"]["snapshot"]["connections"][0]["verification"] == "NETWORK_ONLY"
    assert direct["result"]["snapshot"]["connections"][0]["basis"] == "Shared Docker network only"
    full = analyze(route=["broker-one","ditto-one","db"]).json()
    result = full["result"]
    assert result["feasibility_envelope"][0] == 0 < result["feasibility_envelope"][1]
    assert result["snapshot"]["connections"][1]["basis"] == "Shared Docker network only"
    assert result["snapshot"]["container_ids_by_deployment"]["broker-one"] == ["broker-one-container"]
    assert result["source_deployments"][0]["version"] == "1.5.5"
    steps = result["paths"][0]["transitions"]
    assert steps[0]["conditions"]["A"]["status"] == "T"
    assert all(step["conditions"][key]["status"] == "U" for step in steps for key in "GBHKY")
    assert steps[1]["conditions"]["A"]["status"] == "U"
    assert all(v["status"] == "U" for v in result["paths"][0]["target_impact"].values())
    document = json.loads(next((tmp_path / "live_scenarios").glob(result["provenance"]["sha256"] + ".json")).read_bytes())
    evaluated = build_assessment(document)
    assert not evaluated["scenario_errors"] and not evaluated["input_errors"]
    assert evaluated["scenario_results"][0]["feasibility_envelope"] == result["feasibility_envelope"]
    confirmed = analyze(route=["broker-one","ditto-one","db"], assertion="intended", reference="net-review-5").json()
    assert confirmed["result"]["snapshot"]["connections"][1]["operator_reference"] == "net-review-5"
    assert confirmed["result"]["paths"][0]["transitions"][1]["conditions"]["B"]["status"] == "U"
    assert analyze().json()["report"] == direct["report"]
    rid = full["report"]["report_id"]
    assert rid in {item["report_id"] for item in app("/api/reports").json()["reports"]}
    assert app("/reports/"+rid+".json").json()["context"] == "live"
    assert analyze(route=["broker-one","db"]).status_code == 400
    assert analyze(deployment_id="different-container").status_code == 400
    assert analyze(cve="CVE-2099-0001").json()["status"] == "NOT_ASSESSED"
    inventory.pop("ditto")
    assert app("/api/discovery", {}).ok
    wait(app)
    assert analyze().status_code == 400
    assert app("/api/assessment", {"deployment_id":"broker-one"}).ok
    req["captured_at"] = wait(app)["assessment"]["captured_at"]
    assert analyze().json()["status"] == "NOT_ASSESSED"


def test_unknown_influxdb_cve_saves_component_bounded_context(app, monkeypatch):
    influx = component_deployment("influxdb-lab", "2.7.11", "influxdb", "InfluxDB", "influxdb")
    ditto = component_deployment("ditto-one", "3.9.7", "ditto", "Eclipse Ditto", "ditto")
    monkeypatch.setattr(service, "detect_versions", lambda: {"influx": influx, "ditto": ditto})
    monkeypatch.setattr(service.passive, "collect", lambda row: [])
    candidate = cve("CVE-2024-30896")
    monkeypatch.setattr(service, "search_cves_by_keyword_with_status",
                        lambda *args, **kw: retrieval("COMPLETE", [candidate], 1))

    assert app("/api/discovery", {}).ok
    wait(app)
    assert app("/api/assessment", {"deployment_id": "influxdb-lab"}).ok
    scan = wait(app)["assessment"]
    selected = next(row for row in scan["rows"] if row["cve_id"] == "CVE-2024-30896")
    assert selected["status"] == "UNKNOWN"

    response = app("/api/analyze", {
        "deployment_id": "influxdb-lab", "captured_at": scan["captured_at"], "cve": "CVE-2024-30896",
    })
    assert response.ok
    data = response.json()
    assert data["status"] == "NOT_ASSESSED"
    assert data["assessment_state"] == "APPLICABILITY_UNKNOWN"
    assert data["bounded_context"]["cve"]["status"] == "UNKNOWN"
    assert data["bounded_context"]["terminal_component"] is True
    assert data["bounded_context"]["architecture_position"]["position"] == "terminal"
    assert data["bounded_context"]["numerical_assessment"]["status"] == "NOT_CALCULATED"
    assert "feasibility_envelope" not in data and "paths" not in data
    assert data["bounded_context"]["numerical_assessment"]["status"] != "ZERO"
    assert data["bounded_context"]["potential_consequence_categories"]["status"] == "ADVISORY_CATEGORY_ONLY"
    assert data["bounded_context"]["relationships"]
    assert all(relation["target_product"] != "Healthcare Monitoring"
               for relation in data["bounded_context"]["relationships"])
    assert data["guidance"]["next_action"]["kind"] == "APPLICABILITY_EVIDENCE"

    saved = app("/reports/" + data["report"]["report_id"] + ".json").json()["scenario_evaluation"]
    assert saved["assessment_state"] == "APPLICABILITY_UNKNOWN"
    assert saved["bounded_context"]["deployment"]["deployment_id"] == "influxdb-lab"
    assert saved["missing_evidence"] == data["bounded_context"]["missing_evidence"]
    html = app("/reports/" + data["report"]["report_id"] + ".html").text
    assert "Component-bounded evidence" in html and "APPLICABILITY_UNKNOWN" in html
    assert "Feasibility bounds" in html and "Not calculated" in html
    display_status = "COMPONENT-BOUNDED ASSESSMENT — INCOMPLETE EVIDENCE"
    summary = next(item for item in app("/api/reports").json()["reports"]
                   if item["report_id"] == data["report"]["report_id"])
    assert summary["status"] == "NOT_ASSESSED"
    assert summary["display_status"] == display_status
    assert display_status in html
    assert "Raw engine status" in html
    assert "DO-NOT-EXPOSE" not in json.dumps(saved)


def test_unknown_ditto_cve_keeps_intermediate_position_and_both_relationships_unknown(app, monkeypatch):
    broker = deployment("broker-one", "1.5.5")
    ditto = component_deployment("ditto-one", "3.9.7", "ditto", "Eclipse Ditto", "ditto")
    influx = component_deployment("influxdb-lab", "2.7.11", "influxdb", "InfluxDB", "influxdb")
    monkeypatch.setattr(service, "detect_versions", lambda: {"broker": broker, "ditto": ditto, "influx": influx})
    monkeypatch.setattr(service.passive, "collect", lambda row: [])
    # This is a synthetic workflow case using one UNKNOWN CVE ID from the saved Ditto candidate snapshot.
    candidate = cve("CVE-2026-84197")
    monkeypatch.setattr(service, "search_cves_by_keyword_with_status",
                        lambda *args, **kw: retrieval("COMPLETE", [candidate], 1))

    assert app("/api/discovery", {}).ok
    wait(app)
    assert app("/api/assessment", {"deployment_id": "ditto-one"}).ok
    scan = wait(app)["assessment"]
    data = app("/api/analyze", {
        "deployment_id": "ditto-one", "captured_at": scan["captured_at"], "cve": "CVE-2026-84197",
    }).json()
    assert data["assessment_state"] == "APPLICABILITY_UNKNOWN"
    context = data["bounded_context"]
    assert context["deployment"]["component_id"] == "ditto"
    assert context["architecture_position"]["position"] == "intermediate"
    assert context["terminal_component"] is False
    pairs = {(item["source_product"], item["target_product"]) for item in context["relationships"]}
    assert pairs == {("Mosquitto", "Eclipse Ditto"), ("Eclipse Ditto", "InfluxDB")}
    assert context["assessment_states"]["architecture_path"]["status"] == "NO_VERIFIED_ARCHITECTURE_PATH"
    assert context["numerical_assessment"]["status"] == "NOT_CALCULATED"


def test_affected_influxdb_uses_direct_component_evaluation(app, monkeypatch, tmp_path):
    from ebsr_adapter import build_assessment
    influx = component_deployment("influxdb-lab", "2.7.11", "influxdb", "InfluxDB", "influxdb")
    ditto = component_deployment("ditto-one", "3.9.7", "ditto", "Eclipse Ditto", "ditto")
    monkeypatch.setattr(service, "detect_versions", lambda: {"influx": influx, "ditto": ditto})
    monkeypatch.setattr(service.passive, "collect", lambda row: [])
    candidate = simple("CVE-SYNTH-INFLUX", cpe("influxdb", vendor="influxdata",
                                                version="*", versionEndIncluding="2.7.11"))
    monkeypatch.setattr(service, "search_cves_by_keyword_with_status",
                        lambda *args, **kw: retrieval("COMPLETE", [candidate], 1))

    assert app("/api/discovery", {}).ok
    wait(app)
    assert app("/api/assessment", {"deployment_id": "influxdb-lab"}).ok
    scan = wait(app)["assessment"]
    assert scan["rows"][0]["status"] == "AFFECTED"
    data = app("/api/analyze", {
        "deployment_id": "influxdb-lab", "captured_at": scan["captured_at"], "cve": "CVE-SYNTH-INFLUX",
    }).json()
    assert data["status"] == "EVALUATED"
    result = data["result"]
    assert result["routes"] == [["influxdb-lab"]]
    assert result["component_level"] is True
    step = result["paths"][0]["transitions"][0]
    assert step["transition_type"] == "DIRECT" and step["source"] == step["target"] == "influxdb-lab"
    assert step["conditions"]["A"]["status"] == "T"
    assert all(step["conditions"][key]["status"] == "U" for key in "BGHKY")
    assert all(item["status"] == "U" for item in result["paths"][0]["target_impact"].values())
    assert "Healthcare Monitoring" not in json.dumps(result["snapshot"])
    saved_bundle = next((tmp_path / "live_scenarios").glob(result["provenance"]["sha256"] + ".json"))
    replayed = build_assessment(json.loads(saved_bundle.read_bytes()))
    assert replayed["scenario_results"][0]["feasibility_envelope"] == result["feasibility_envelope"]


def test_discovery_projects_only_endpoint_host_and_network_aliases():
    from version_detector import _architecture_metadata
    values = _architecture_metadata({"Name":"/client","Config":{"Env":[
        "MQTT_BROKER_URL=mqtt://user:private@broker:1883/path?token=sensitive",
        "OTHER_SECRET=private"]},"NetworkSettings":{"Networks":{"lab":{"Aliases":["client"]}}}})
    assert values["endpoint_hosts"] == {"MQTT_BROKER_URL":"broker"}
    assert values["networks"] == {"lab":["client"]}
    assert "private" not in str(values) and "sensitive" not in str(values)


def test_generated_route_rejects_runtime_identity_change_and_handles_ambiguous_targets():
    from assessment_web import live_scenarios
    source = dict(product="Mosquitto", component_id="mosquitto", deployment_id="broker", version="1.5.5",
                  container_ids=["original-id"], assessable=True)
    first = dict(source, product="Eclipse Ditto", component_id="ditto", deployment_id="first", container_ids=["a"])
    second = dict(first, deployment_id="second", container_ids=["b"])
    discovery = dict(captured_at="2026-01-01T00:00:00Z",status="COMPLETE",supported=[source,first,second])
    scan = dict(captured_at="2026-01-01T00:01:00Z", deployment=source,
                rows=[dict(cve_id="CVE-2018-12546",status="AFFECTED")])
    request = dict(deployment_id="broker", captured_at=scan["captured_at"], cve="CVE-2018-12546")
    result = live_scenarios.analyze(discovery,scan,request,None)
    assert result["status"] == "CHOOSE_ROUTE" and len(result["routes"]) == 2
    invalidated = live_scenarios.analyze(
        discovery,scan,dict(request,route=["broker","removed"]),None,require_explicit_route=True)
    assert invalidated["status"] == "CHOOSE_ROUTE" and invalidated["route_invalidated"] is True
    assert invalidated["routes"] == [["broker","first"],["broker","second"]]
    discovery["supported"][0] = dict(source, container_ids=["replacement-id"])
    with pytest.raises(service.AssessmentError, match="identity"):
        live_scenarios.routes(discovery, scan)


def test_ambiguous_route_outcome_is_saved_once(app,monkeypatch):
    broker = deployment("broker-one","1.5.5")
    first = {**deployment("ditto-one","3.9.7"),"component_id":"ditto","display_name":"Eclipse Ditto"}
    second = {**deployment("ditto-two","3.9.7"),"component_id":"ditto","display_name":"Eclipse Ditto"}
    monkeypatch.setattr(service,"detect_versions",lambda:{"broker":broker,"first":first,"second":second})
    monkeypatch.setattr(service.passive,"collect",lambda row:[])
    candidate = simple("CVE-2018-12546",cpe("mosquitto"),metrics={"cvssMetricV31":[
        metric_entry(6.5,vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N")]})
    monkeypatch.setattr(service,"search_cves_by_keyword_with_status",
                        lambda *args,**kw:retrieval("COMPLETE",[candidate],1))
    assert app("/api/discovery",{}).ok
    wait(app)
    assert app("/api/assessment",{"deployment_id":"broker-one"}).ok
    scan = wait(app)["assessment"]
    request = {"deployment_id":"broker-one","captured_at":scan["captured_at"],"cve":"CVE-2018-12546"}
    first_response = app("/api/analyze",request).json()
    second_response = app("/api/analyze",request).json()
    assert first_response["status"] == second_response["status"] == "CHOOSE_ROUTE"
    assert first_response["report"]["report_id"] == second_response["report"]["report_id"]
    saved = app("/reports/"+first_response["report"]["report_id"]+".json").json()
    assert saved["scenario_evaluation"]["status"] == "CHOOSE_ROUTE"
    reports = app("/api/reports").json()["reports"]
    choose_route = [item for item in reports if item["status"] == "CHOOSE_ROUTE"]
    assert [item["report_id"] for item in choose_route] == [first_response["report"]["report_id"]]
    # The initial scan has its own stable report; repeating the ambiguous analysis must not add another.
    assert len(reports) == 2
