"""Passive collection and application route tests. All external services are fixtures."""
from datetime import datetime, timedelta, timezone
import json

import pytest

from assessment_web import passive, service
from test_assessment_web import app, wait, deployment, retrieval
from testutil import cpe, simple, metric_entry
from version_detector import _architecture_metadata

START = "2026-01-01T00:00:00Z"
IDS = {name: ch * 64 for name, ch in zip(("mqtt","gateway","connectivity","db"), "abcd")}


class Stack:
    def __init__(self):
        self.duplicate_alias = False
        self.old_metric = False
        self.missing_file = False
        self.restarted = False
        self.api_error = None
        self.connections = ["sensor-source","writer-sink"]
        self.inbound_uri = "tcp://user:NEVER-STORE@mqtt:1883"
        self.outbound_uri = "http://host.docker.internal:8095"
        self.writer_metadata = True
        self.unsupported_connections = set()

    def container(self, name):
        port = {"mqtt":"1883","gateway":"8080","db":"8086"}.get(name)
        aliases = [name]
        if name == "db" and self.duplicate_alias:
            aliases.append("mqtt")
        return {"Id":IDS[name],"Image":"sha256:"+"1"*64,"Name":"/"+name,
                "State":{"StartedAt":START,"Status":"running"},
                "Config":{"Labels":{"com.docker.compose.service":name}},
                "NetworkSettings":{"Networks":{"lab":{"Aliases":aliases}},
                                   "Ports":{port+"/tcp":[{"HostIp":"127.0.0.1","HostPort":port}]} if port else {}}}

    def inventory(self):
        result = {}
        for component, version, title, names, dep in [
            ("mosquitto","1.5.5","Mosquitto",["mqtt"],"broker"),
            ("ditto","3.9.7","Eclipse Ditto",["gateway","connectivity"],"docker"),
            ("influxdb","2.7.11","InfluxDB",["db"],"influx")]:
            result[dep] = {**deployment(dep, version),"component_id":component,"architecture_component":title,
                           "architecture_metadata":[_architecture_metadata(self.container(n)) for n in names],
                           "container_ids":[IDS[n] for n in names]}
        return result

    def run(self, args):
        status = "COMPLETE"
        if args[1] == "context":
            out = "unix:///var/run/docker.sock"
        elif args[1] == "inspect":
            name = next(n for n, cid in IDS.items() if cid == args[-1])
            container = self.container(name)
            out = (json.dumps(container["NetworkSettings"]) if "json" in args[-2] else
                   " ".join([IDS[name],container["Image"],"changed" if self.restarted else START,"true"]))
        elif args[1] == "exec":
            if args[-1] == "/private/path":
                out = "user publisher\ntopic read private/NEVER-STORE/#\ntopic write sensors/NEVER-STORE\ntopic deny admin/#\n"
            else:
                out = "listener 1883\nallow_anonymous false\nacl_file /private/path\npassword_file /sensitive\nremote_password NEVER-STORE\ncheck_retain_source true\npersistence true\n"
            if self.missing_file:
                status = "DOCKER_ERROR"
        elif args[1] == "logs":
            out = 'New client connected from 127.0.0.1 NEVER-STORE\nPOST /api/v2/write?token=NEVER-STORE HTTP/1.1" 204'
        else:
            raise AssertionError(args)
        return {"status":status,"stdout":out,"stderr":""}

    def get(self, port, path, component):
        if self.api_error:
            raise passive.Unavailable(self.api_error)
        if component == "influxdb":
            name = path.split("/")[-1].split("?")[0]
            return {name:[{"id":"1"*16,"name":"NEVER-STORE"}]}
        if component == "writer":
            if not self.writer_metadata:
                raise passive.Unavailable("API unreachable or invalid JSON")
            return {"service":"ditto-influx-telemetry","host":"localhost","port":8086}
        if path.endswith("connections"):
            return self.connections
        cid = path.split("/")[4]
        if cid in self.unsupported_connections:
            return {"id":cid,"connectionType":"amqp-10","uri":"amqp://mqtt:5672",
                    "sources":[{"addresses":["ignored"]}]}
        inbound = cid == "sensor-source"
        if path.endswith("/status"):
            return {"connectionId":cid,"liveStatus":"open"}
        if path.endswith("/metrics"):
            return {"connectionId":cid,"connectionMetrics":{
                "inbound" if inbound else "outbound":{"consumed" if inbound else "dispatched":{
                    "success":{"PT1M":1,"lastMessageAt":START if self.old_metric else passive.utc()}}}}}
        return ({"id":cid,"connectionType":"mqtt","uri":self.inbound_uri,
                 "sources":[{"addresses":["private/NEVER-STORE"],"authorizationContext":["private"]}]}
                if inbound else {"id":cid,"connectionType":"http-push","uri":self.outbound_uri,
                                 "targets":[{"address":"POST:/events","topics":["thing-events"]}]})

    def install(self, monkeypatch):
        monkeypatch.delenv("DOCKER_HOST", raising=False)
        collect = passive.collect
        binding = passive.binding_unchanged
        monkeypatch.setattr(service,"detect_versions",self.inventory)
        monkeypatch.setattr(passive,"collect",lambda row:collect(row,self.run,self.get))
        monkeypatch.setattr(passive,"binding_unchanged",lambda member:binding(member,self.run))
        item = simple("CVE-2018-12546", cpe("mosquitto"), metrics={"cvssMetricV31":[
            metric_entry(6.5,vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N")]})
        monkeypatch.setattr(service,"search_cves_by_keyword_with_status",lambda *args,**kw:retrieval("COMPLETE",[item],1))


def test_bound_connections_drive_only_relationship_condition(app, monkeypatch):
    lab = Stack()
    lab.install(monkeypatch)
    assert app("/api/discovery",{}).ok
    discovery = wait(app)["discovery"]
    assert "NEVER-STORE" not in json.dumps(discovery)
    assert app("/api/assessment",{"deployment_id":"broker"}).ok
    scan = wait(app)["assessment"]
    req = {"deployment_id":"broker","captured_at":scan["captured_at"],"cve":"CVE-2018-12546",
           "route":["broker","docker","influx"]}
    data = app("/api/analyze",req).json()
    result = data["result"]
    first, second = result["snapshot"]["connections"]
    assert first["verification"] == "OBSERVED_COMMUNICATION"
    assert first["target_product"] == "Eclipse Ditto" and first["target"] == "docker"
    assert second["verification"] == "VERIFIED_CONFIGURATION"
    assert second["records"][0]["via"] == "Telemetry writer"
    steps = result["paths"][0]["transitions"]
    assert [s["conditions"]["B"]["status"] for s in steps] == ["T","T"]
    assert all(s["conditions"][k]["status"] == "U" for s in steps for k in "GHKY")
    assert result["paths"][0]["target_impact"]["I"]["status"] == "U"
    guidance = result["evidence_guidance"]
    layers = {item["key"]: item["status"] for item in guidance["layers"]}
    assert layers["configuration"] == "VERIFIED" and layers["communication"] == "OBSERVED"
    assert layers["cve"] == "U" and layers["impact"] == "U"
    assert guidance["receiver"]["status"] == "U"
    assert any("ordinary communication was observed" in item for item in guidance["verified"])
    report = app("/reports/"+data["report"]["report_id"]+".html")
    assert "Evidence collected" in report.text and "Communication observed" in report.text
    assert "Configuration verified" in report.text and "NEVER-STORE" not in report.text
    lab.restarted = True
    assert app("/api/analyze",req).status_code == 400


def test_failed_and_stale_evidence_remains_explicit(monkeypatch):
    lab = Stack()
    lab.install(monkeypatch)
    lab.missing_file = True
    lab.api_error = "HTTP 403"
    rows = service.deployments()["supported"]
    assert "unavailable" in str(rows[0]["inspections"][0]["issues"])
    assert "HTTP 403" in str(rows[1]["inspections"])
    lab.api_error = None
    lab.old_metric = True
    discovery = service.deployments()
    mqtt, ditto, _ = discovery["supported"]
    match, = passive.match_connections(mqtt,ditto,discovery,passive.utc())
    assert not match["observed"]
    for item in ditto["inspections"]:
        item["started"] = (datetime.now(timezone.utc)-timedelta(hours=1)).isoformat()
    assert not passive.match_connections(mqtt,ditto,discovery,passive.utc())
    lab.duplicate_alias = True
    discovery = service.deployments()
    mqtt, ditto, _ = discovery["supported"]
    assert not passive.match_connections(mqtt,ditto,discovery,passive.utc())


def test_config_projection_and_log_redaction(monkeypatch):
    lab = Stack()
    row = lab.inventory()["broker"]
    item, = passive.collect(row,lab.run,lab.get)
    assert item["mosquitto_file"]["directives"] == {"listener":[1883],"allow_anonymous":["false"],
        "acl_file_present":True,"password_file_present":True,"check_retain_source":["true"],"persistence":["true"]}
    assert item["mosquitto_security"]["authentication_required"] is True
    assert item["mosquitto_security"]["acl_summary"]["rules"] == 3
    assert item["mosquitto_security"]["acl_summary"]["access"] == {"read":1,"write":1,"readwrite":0,"deny":1}
    assert item["log_events"]["broker_client_connected"] == 1
    assert "/private/path" not in str(item) and "/sensitive" not in str(item) and "NEVER-STORE" not in str(item)
    monkeypatch.setenv("DOCKER_HOST","tcp://remote:2376")
    monkeypatch.delenv("DOCKER_CONTEXT",raising=False)
    record, = passive.collect(lab.inventory()["influx"],lab.run,lab.get)
    assert "Local Docker engine binding unverified" in str(record["issues"])


def test_writer_metadata_is_read_only_and_contains_no_credentials():
    from http.server import ThreadingHTTPServer
    from threading import Thread
    from urllib.request import urlopen
    from lab.ditto_influx_telemetry.writer import Writer, make_handler
    writer = Writer({"expected_thing_id":"hidden-thing","influx_url":"http://user:NEVER-STORE@localhost:8086",
                     "influx_org":"org","influx_bucket":"bucket","state_file":"unused"}, "NEVER-STORE")
    with ThreadingHTTPServer(("127.0.0.1",0),make_handler(writer)) as server:
        thread = Thread(target=server.handle_request)
        thread.start()
        with urlopen(f"http://127.0.0.1:{server.server_port}/assessment-metadata",timeout=3) as response:
            data = json.load(response)
        thread.join(3)
        assert data == {"service":"ditto-influx-telemetry","host":"localhost","port":8086,"last_accepted_at":None}


def test_unpublished_api_uses_fixed_read_only_command(monkeypatch):
    from types import SimpleNamespace
    captured = {}
    def invoke(args, **kwargs):
        captured.update(args=args, **kwargs)
        return SimpleNamespace(returncode=0,stdout=b"[]\n200")
    monkeypatch.setattr(passive.subprocess,"run",invoke)
    monkeypatch.setenv("RISKSCOPE_DITTO_DEPLOYMENT_ID","docker")
    monkeypatch.setenv("RISKSCOPE_DITTO_USER","reader")
    monkeypatch.setenv("RISKSCOPE_DITTO_PASSWORD","NEVER-STORE")
    get = passive.container_api({"member_id":IDS["gateway"]},{"deployment_id":"docker"})
    assert get(8080,"/api/2/connections","ditto") == []
    assert captured["input"].startswith(b"Authorization: Basic ")
    assert "NEVER-STORE" not in str(captured["args"]) and "shell" not in captured
    with pytest.raises(passive.Unavailable):
        get(8080,"/unrelated","ditto")


@pytest.mark.parametrize(("error","expected"), [
    ("HTTP 401","AUTHENTICATION_REQUIRED"),
    ("HTTP 403","PERMISSION_DENIED"),
    ("HTTP 404","API_ENDPOINT_INCOMPATIBLE"),
    ("API unreachable or invalid JSON","DISCOVERY_FAILED"),
])
def test_connection_inventory_authentication_and_permission_failures(monkeypatch,error,expected):
    lab = Stack()
    lab.api_error = error
    lab.install(monkeypatch)
    discovery = service.deployments()
    mqtt, ditto, _ = discovery["supported"]
    inventory = next(item["connection_inventory"] for item in ditto["inspections"]
                     if "connection_inventory" in item)
    assert inventory["status"] == expected
    relation = passive.relationship(mqtt,ditto,discovery,discovery["captured_at"],["lab"])
    assert relation["state"] == "NETWORK_ONLY"
    assert error in relation["reason"]
    assert "NEVER-STORE" not in json.dumps(relation)


def test_empty_or_wrong_connection_is_not_configured(monkeypatch):
    lab = Stack(); lab.install(monkeypatch)
    lab.connections = []
    discovery = service.deployments()
    mqtt, ditto, _ = discovery["supported"]
    relation = passive.relationship(mqtt,ditto,discovery,discovery["captured_at"],["lab"])
    assert relation["state"] == "NOT_CONFIGURED"
    assert relation["inventory"][0]["status"] == "NO_CONNECTIONS"

    lab.connections = ["sensor-source", "writer-sink"]
    lab.inbound_uri = "tcp://user:NEVER-STORE@different-broker:1883"
    discovery = service.deployments()
    mqtt, ditto, _ = discovery["supported"]
    relation = passive.relationship(mqtt,ditto,discovery,discovery["captured_at"],["lab"])
    assert relation["state"] == "NOT_CONFIGURED"
    assert "exact deployment pair" in relation["reason"]


def test_shared_network_without_authenticated_configuration_remains_network_only(monkeypatch):
    lab = Stack(); lab.api_error = "HTTP 401"; lab.install(monkeypatch)
    discovery = service.deployments()
    mqtt, ditto, _ = discovery["supported"]
    relation = passive.relationship(mqtt,ditto,discovery,discovery["captured_at"],["lab"])
    assert relation["state"] == "NETWORK_ONLY"
    assert relation["meaning"].startswith("The deployments share")


def test_shared_network_alone_does_not_establish_ebsr_relationship(app,monkeypatch):
    lab = Stack(); lab.api_error = "HTTP 401"; lab.install(monkeypatch)
    assert app("/api/discovery",{}).ok
    discovery = wait(app)["discovery"]
    assert app("/api/assessment",{"deployment_id":"broker"}).ok
    scan = wait(app)["assessment"]
    result = app("/api/analyze",{"deployment_id":"broker","captured_at":scan["captured_at"],
        "cve":"CVE-2018-12546"}).json()["result"]
    assert result["snapshot"]["connections"][0]["verification"] == "NETWORK_ONLY"
    step = result["paths"][0]["transitions"][0]
    assert [step["conditions"][key]["status"] for key in "AGHBKY"] == ["T","U","U","U","U","U"]
    assert result["paths"][0]["target_impact"]["I"]["status"] == "U"


def test_configured_connection_without_traffic_establishes_only_relationship(app,monkeypatch):
    lab = Stack(); lab.old_metric = True; lab.install(monkeypatch)
    assert app("/api/discovery",{}).ok
    discovery = wait(app)["discovery"]
    mqtt, ditto, _ = discovery["supported"]
    relation = passive.relationship(mqtt,ditto,discovery,discovery["captured_at"],["lab"])
    assert relation["state"] == "VERIFIED_CONFIGURATION"
    assert not any(item["observed"] for item in relation["records"])
    assert app("/api/assessment",{"deployment_id":"broker"}).ok
    scan = wait(app)["assessment"]
    response = app("/api/analyze",{"deployment_id":"broker","captured_at":scan["captured_at"],
        "cve":"CVE-2018-12546","route":["broker","docker"]})
    result = response.json()["result"]
    assert result["snapshot"]["connections"][0]["verification"] == "VERIFIED_CONFIGURATION"
    step = result["paths"][0]["transitions"][0]
    assert step["conditions"]["B"]["status"] == "T"
    assert step["conditions"]["K"]["status"] == "U"
    assert step["conditions"]["Y"]["status"] == "U"


def test_missing_and_unresolved_influx_integration_remain_distinct(monkeypatch):
    lab = Stack(); lab.install(monkeypatch)
    lab.connections = ["sensor-source"]
    discovery = service.deployments()
    _, ditto, influx = discovery["supported"]
    relation = passive.relationship(ditto,influx,discovery,discovery["captured_at"],["lab"])
    assert relation["state"] == "NOT_CONFIGURED"

    lab.connections = ["sensor-source", "writer-sink"]
    lab.writer_metadata = False
    discovery = service.deployments()
    _, ditto, influx = discovery["supported"]
    relation = passive.relationship(ditto,influx,discovery,discovery["captured_at"],["lab"])
    assert relation["state"] == "UNKNOWN"
    assert "storage destination" in relation["reason"]


def test_uninterpreted_connection_inventory_never_claims_not_configured(monkeypatch):
    lab = Stack(); lab.install(monkeypatch)
    lab.connections = ["legacy-protocol"]
    lab.unsupported_connections = {"legacy-protocol"}
    discovery = service.deployments()
    mqtt, ditto, _ = discovery["supported"]
    relation = passive.relationship(mqtt,ditto,discovery,discovery["captured_at"],["lab"])
    assert relation["state"] == "UNKNOWN"
    assert relation["inventory"][0]["status"] == "AVAILABLE"
    assert relation["inventory"][0]["failed_records"] == 1
    assert "could not be interpreted" in relation["reason"]
    assert "NEVER-STORE" not in json.dumps(relation)


def test_unrelated_uninterpreted_record_does_not_invalidate_matching_mqtt_configuration(monkeypatch):
    lab = Stack(); lab.install(monkeypatch)
    lab.connections = ["sensor-source", "legacy-protocol"]
    lab.unsupported_connections = {"legacy-protocol"}
    lab.old_metric = True
    discovery = service.deployments()
    mqtt, ditto, _ = discovery["supported"]
    relation = passive.relationship(mqtt,ditto,discovery,discovery["captured_at"],["lab"])
    assert relation["state"] == "VERIFIED_CONFIGURATION"
    assert relation["records"][0]["connection_id"] == "sensor-source"
    assert not any(item["observed"] for item in relation["records"])
    assert relation["inventory"][0]["failed_records"] == 1
    assert "could not be interpreted" in relation["inventory"][0]["reason"]


def test_connection_metadata_redacts_credentials_topics_and_mapping_names():
    record = passive.connection_record({
        "id":"source", "connectionType":"mqtt", "uri":"tcp://reader:NEVER-STORE@mqtt:1883",
        "sources":[{"addresses":["private/NEVER-STORE"],"authorizationContext":["private/NEVER-STORE"],
                    "payloadMapping":"mapping-secret-name"}],
        "mappingDefinitions":{"mapping-secret-name":{"mapping":"secret expression"}},
    })
    rendered = json.dumps(record)
    assert record["endpoint"] == {"host":"mqtt","port":1883,"scheme":"tcp","write_path":False}
    assert record["has_authorization_context"] is True and record["has_payload_mapping"] is True
    assert "NEVER-STORE" not in rendered and "mapping-secret-name" not in rendered
    assert record["source_address_fingerprints"] and record["mapping_fingerprints"]


def test_authenticated_published_ditto_inventory(monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get("Authorization", ""))
            body = b"[]"
            self.send_response(200); self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self, *args):
            return
    with ThreadingHTTPServer(("127.0.0.1",0),Handler) as server:
        thread = Thread(target=server.handle_request)
        thread.start()
        monkeypatch.setenv("RISKSCOPE_DITTO_API_PORT",str(server.server_port))
        monkeypatch.setenv("RISKSCOPE_DITTO_USER","reader")
        monkeypatch.setenv("RISKSCOPE_DITTO_PASSWORD","test-only-secret")
        assert passive.read_api(server.server_port,"/api/2/connections","ditto") == []
        thread.join(3)
    assert seen == ["Basic cmVhZGVyOnRlc3Qtb25seS1zZWNyZXQ="]


def test_live_collection_preserves_experimental_evidence(app,monkeypatch):
    import hashlib
    paths = [
        service.ROOT / "scenarios" / "ebsr_cve_2018_12546_experiment_v9.json",
        service.ROOT / "output/evidence_runs/cve-2018-12546-downstream-20261118T200923198752Z-readback.json",
    ]
    before = [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths]
    lab = Stack(); lab.install(monkeypatch)
    assert app("/api/discovery",{}).ok
    wait(app)
    assert app("/api/assessment",{"deployment_id":"broker"}).ok
    wait(app)
    after = [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths]
    assert after == before


def test_evidence_refresh_recollects_and_reevaluates_the_same_deployment(app,monkeypatch):
    lab = Stack(); lab.api_error = "HTTP 401"; lab.install(monkeypatch)
    assert app("/api/discovery",{}).ok
    first = wait(app)
    assert app("/api/assessment",{"deployment_id":"broker"}).ok
    first_scan = wait(app)["assessment"]
    route = ["broker","docker","influx"]
    initial = app("/api/analyze",{"deployment_id":"broker","captured_at":first_scan["captured_at"],
                                  "cve":"CVE-2018-12546","route":route}).json()
    assert initial["result"]["snapshot"]["connections"][0]["verification"] == "NETWORK_ONLY"
    initial_report = initial["report"]["report_id"]

    lab.api_error = None
    accepted = app("/api/refresh-architecture",{
        "deployment_id":"broker", "captured_at":first_scan["captured_at"],
        "discovery_captured_at":first["discovery"]["captured_at"], "cve":"CVE-2018-12546", "route":route,
    })
    assert accepted.ok, accepted.text
    refreshed = wait(app)
    assert refreshed["job"]["kind"] == "refresh"
    assert refreshed["job"]["refresh_status"] == "CHANGED"
    assert refreshed["assessment"]["captured_at"] != first_scan["captured_at"]
    result = refreshed["live_analysis"]["result"]
    assert result["route"] == route
    assert result["snapshot"]["connections"][0]["verification"] == "OBSERVED_COMMUNICATION"
    assert [step["conditions"]["B"]["status"] for step in result["paths"][0]["transitions"]] == ["T","T"]
    assert all(step["conditions"][key]["status"] == "U"
               for step in result["paths"][0]["transitions"] for key in "GHKY")
    assert all(item["status"] == "U" for item in result["paths"][0]["target_impact"].values())
    assert refreshed["live_analysis"]["report"]["report_id"] != initial_report
    assert refreshed["results"]["live"]["snapshot"]["connections"][0]["next_action_kind"] == "CONTROLLED_VALIDATION"


def test_unchanged_refresh_does_not_duplicate_reports(app,monkeypatch):
    lab = Stack(); lab.install(monkeypatch)
    assert app("/api/discovery",{}).ok
    discovery = wait(app)["discovery"]
    assert app("/api/assessment",{"deployment_id":"broker"}).ok
    scan = wait(app)["assessment"]
    route = ["broker","docker"]
    analyzed = app("/api/analyze",{"deployment_id":"broker","captured_at":scan["captured_at"],
                                   "cve":"CVE-2018-12546","route":route})
    assert analyzed.ok, analyzed.text
    before = app("/api/session").json()
    report_count = len(app("/api/reports").json()["reports"])
    accepted = app("/api/refresh-architecture",{
        "deployment_id":"broker", "captured_at":scan["captured_at"],
        "discovery_captured_at":discovery["captured_at"], "cve":"CVE-2018-12546", "route":route,
    })
    assert accepted.ok, accepted.text
    refreshed = wait(app)
    assert refreshed["job"]["refresh_status"] == "UNCHANGED"
    assert refreshed["assessment"]["captured_at"] == before["assessment"]["captured_at"]
    assert len(app("/api/reports").json()["reports"]) == report_count


def test_refresh_failure_keeps_previous_evidence_and_rejects_stale_identity(app,monkeypatch):
    lab = Stack(); lab.install(monkeypatch)
    assert app("/api/discovery",{}).ok
    discovery = wait(app)["discovery"]
    assert app("/api/assessment",{"deployment_id":"broker"}).ok
    scan = wait(app)["assessment"]
    request = {"deployment_id":"broker","captured_at":scan["captured_at"],
               "discovery_captured_at":discovery["captured_at"],"cve":"CVE-2018-12546",
               "route":["broker","docker"]}
    stale = dict(request, captured_at="2026-01-01T00:00:00Z")
    assert app("/api/refresh-architecture",stale).status_code == 400
    monkeypatch.setattr(service,"deployments",lambda progress=None:{
        "status":"DOCKER_UNAVAILABLE","supported":[],"other":[],"captured_at":"2026-02-01T00:00:00Z"})
    assert app("/api/refresh-architecture",request).ok
    for _ in range(300):
        state = app("/api/session").json()
        if state["job"]["state"] != "running":
            break
        sleep(0.015)
    else:
        pytest.fail("refresh did not finish")
    assert state["job"]["state"] == "error"
    assert state["job"]["refresh_status"] == "FAILED"
    assert "previous evidence was retained" in state["job"]["message"]
    assert state["assessment"] == scan and state["discovery"] == discovery
