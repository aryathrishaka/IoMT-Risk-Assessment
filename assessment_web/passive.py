"""Passive observations for a single Docker discovery snapshot. Never persist raw responses."""
from datetime import datetime, timedelta, timezone
import base64
import subprocess
from time import monotonic
import hashlib
import json
import os
import re
from urllib.parse import quote, urlsplit

import requests

from version_detector import _run_docker, DISCOVERY_COMPLETE

MAX_AGE = timedelta(minutes=15)
HEX_ID = re.compile(r"[0-9a-f]{64}")
SLUG = re.compile(r"[a-zA-Z0-9_.:-]{1,128}")

VERIFIED_CONFIGURATION = "VERIFIED_CONFIGURATION"
OBSERVED_COMMUNICATION = "OBSERVED_COMMUNICATION"
NETWORK_ONLY = "NETWORK_ONLY"
UNKNOWN = "UNKNOWN"
NOT_CONFIGURED = "NOT_CONFIGURED"

RELATIONSHIP_STATE_MEANINGS = {
    VERIFIED_CONFIGURATION: "The inspected component configuration names the exact peer deployment and required endpoint, but no traffic was observed in this window.",
    OBSERVED_COMMUNICATION: "An exact deployment-bound application configuration and successful traffic counters in the collection window support ordinary communication. This is not vulnerability propagation.",
    NETWORK_ONLY: "The deployments share a Docker network or endpoint namespace, but application configuration and communication are not established.",
    UNKNOWN: "The available evidence cannot distinguish configuration, communication, or non-configuration, including when the connection inventory is unavailable or incomplete.",
    NOT_CONFIGURED: "A successfully inspected configuration source contains no matching application connection for the exact deployment pair and direction.",
}


def utc():
    return datetime.now(timezone.utc).isoformat()


def instant(value):
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return timestamp if timestamp.tzinfo else None
    except (TypeError, AttributeError, ValueError):
        return None


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def mosquitto_config(text):
    directives = {}
    for line in text.splitlines():
        words = line.strip().split()
        if len(words) < 2 or words[0].startswith("#"):
            continue
        key, value = words[:2]
        if key in {"allow_anonymous", "persistence", "check_retain_source", "retain_available",
                   "per_listener_settings"} and value.lower() in {"true", "false"}:
            directives.setdefault(key, []).append(value.lower())
        elif key == "listener" and value.isdecimal() and 0 < int(value) <= 65535:
            directives.setdefault(key, []).append(int(value))
        elif key == "address":
            remote = endpoint("mqtt://" + value)
            if remote:
                directives.setdefault("bridge_endpoints", []).append(f"{remote['host']}:{remote['port']}")
        elif key in {"acl_file", "password_file", "connection", "include_dir", "plugin", "auth_plugin"}:
            directives[key + "_present"] = True
    return directives


def mosquitto_values(text, key):
    values = []
    for line in text.splitlines():
        words = line.strip().split()
        if len(words) >= 2 and not words[0].startswith("#") and words[0] == key:
            values.append(words[1])
    return values


def mosquitto_acl_summary(text):
    """Summarise ACL rules without retaining usernames or configured topic names."""
    access = {"read": 0, "write": 0, "readwrite": 0, "deny": 0}
    user_blocks = 0
    rules = 0
    current_scope = "anonymous"
    scopes = []
    for raw in text.splitlines():
        words = raw.strip().split()
        if not words or words[0].startswith("#"):
            continue
        keyword = words[0].lower()
        if keyword == "user":
            user_blocks += 1
            current_scope = "user"
            if current_scope not in scopes:
                scopes.append(current_scope)
            continue
        if keyword == "topic" and current_scope not in scopes:
            scopes.append(current_scope)
        if keyword not in {"topic", "pattern"}:
            continue
        action = words[1].lower() if len(words) > 1 else "readwrite"
        action = action if action in access else "readwrite"
        access[action] += 1
        rules += 1
    return {"rules": rules, "access": access, "user_blocks": user_blocks,
            "scopes": scopes,
            "limitation": "ACL usernames and topic literals are intentionally not persisted."}


def mosquitto_security_summary(directives):
    anonymous = directives.get("allow_anonymous", [])
    return {
        "authentication_required": anonymous == ["false"],
        "password_file_referenced": bool(directives.get("password_file_present")),
        "external_auth_plugin_referenced": bool(directives.get("plugin_present") or directives.get("auth_plugin_present")),
        "per_listener_settings": directives.get("per_listener_settings", []),
        "acl_file_referenced": bool(directives.get("acl_file_present")),
        "listeners": directives.get("listener", []),
        "retained_message_settings": {key: directives.get(key, []) for key in
                                      ("retain_available", "persistence", "check_retain_source")},
        "limitation": "This is evidence from configured files, not proof of the effective loaded listener policy.",
    }


def endpoint(uri):
    try:
        parts = urlsplit(uri)
        if parts.scheme not in {"mqtt", "mqtts", "tcp", "ssl", "http", "https"} or not parts.hostname:
            return None
        host = parts.hostname
        if not re.fullmatch(r"[a-z0-9.-]{1,253}", host):
            return None
        port = parts.port or {"mqtt":1883,"tcp":1883,"mqtts":8883,"ssl":8883,"http":80,"https":443}[parts.scheme]
        return {"host":host, "port":port, "scheme":parts.scheme, "write_path":parts.path == "/api/v2/write"}
    except (ValueError, TypeError, AttributeError):
        return None


class Unavailable(Exception):
    """Only constant labels and HTTP status numbers may be included."""


def inventory_failure_status(message):
    if "HTTP 401" in message:
        return "AUTHENTICATION_REQUIRED"
    if "HTTP 403" in message:
        return "PERMISSION_DENIED"
    if "HTTP 404" in message:
        return "API_ENDPOINT_INCOMPATIBLE"
    return "DISCOVERY_FAILED"


def safe_config_values(values):
    """Keep short connection labels while dropping credentials and unbounded values."""
    result = []
    for value in values if isinstance(values, list) else []:
        if not isinstance(value, str) or len(value) > 200 or "\n" in value or "\r" in value:
            continue
        if re.search(r"(?i)(?:password|passwd|secret|token|credential|authorization)\s*[:=]", value):
            continue
        if value not in result:
            result.append(value)
    return result[:16]


def read_api(port, path, component):
    if component != "writer":
        bound_port = os.getenv("RISKSCOPE_" + ("DITTO" if component == "ditto" else "INFLUX") + "_API_PORT")
    else:
        bound_port = None
    with requests.Session() as client:
        client.trust_env = False
        if bound_port == str(port) and component == "ditto" and os.getenv("RISKSCOPE_DITTO_USER") and os.getenv("RISKSCOPE_DITTO_PASSWORD"):
            client.auth = (os.environ["RISKSCOPE_DITTO_USER"], os.environ["RISKSCOPE_DITTO_PASSWORD"])
        if bound_port == str(port) and component == "influxdb" and os.getenv("RISKSCOPE_INFLUX_READ_TOKEN"):
            client.headers["Authorization"] = "Token " + os.environ["RISKSCOPE_INFLUX_READ_TOKEN"]
        try:
            with client.get(f"http://127.0.0.1:{port}{path}", allow_redirects=False, stream=True,
                            timeout=(2, 3)) as response:
                if response.status_code != 200:
                    raise Unavailable(f"HTTP {response.status_code}")
                deadline = monotonic() + 6
                chunks = bytearray()
                for part in response.iter_content(16384):
                    chunks.extend(part)
                    if len(chunks) > 524288 or monotonic() > deadline:
                        raise Unavailable("Response exceeded collection limit")
                return json.loads(chunks)
        except (requests.RequestException, ValueError) as exc:
            raise Unavailable("API unreachable or invalid JSON") from exc


def container_api(member, row):
    """Read an unpublished API inside its identified member. Credentials travel on stdin."""
    def get(port, path, component):
        if component == "writer":
            return read_api(port, path, component)
        if not re.fullmatch(r"/api/(?:2/connections(?:/[a-zA-Z0-9_.:%-]+(?:/(?:metrics|status))?)?|v2/(?:orgs|buckets)\?limit=100)", path):
            raise Unavailable("Unsupported local API path")
        header = ""
        if os.getenv("RISKSCOPE_DITTO_DEPLOYMENT_ID") == row["deployment_id"] and component == "ditto":
            user, password = os.getenv("RISKSCOPE_DITTO_USER"), os.getenv("RISKSCOPE_DITTO_PASSWORD")
            if user and password:
                header = "Authorization: Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        if os.getenv("RISKSCOPE_INFLUX_DEPLOYMENT_ID") == row["deployment_id"] and component == "influxdb":
            token = os.getenv("RISKSCOPE_INFLUX_READ_TOKEN", "")
            if token and token.isascii() and token.isprintable():
                header = "Authorization: Token " + token
        try:
            response = subprocess.run(["docker","exec","-i",member["member_id"],"/usr/bin/curl","-q","-s",
                "--noproxy","*","--max-time","3","--max-filesize","524288","-w","\n%{http_code}",
                "--header","@-","--",f"http://127.0.0.1:{port}{path}"],
                input=(header+"\n").encode() if header else b"", capture_output=True,timeout=6,check=False)
            body, _, status = response.stdout.rpartition(b"\n")
            if response.returncode:
                raise Unavailable("Container API client unavailable or GET failed")
            if status != b"200":
                raise Unavailable("Container GET returned HTTP " + (status.decode() if status.isdigit() else "error"))
            if len(body) > 524288:
                raise Unavailable("Response exceeded collection limit")
            return json.loads(body)
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            raise Unavailable("Container API unavailable or invalid JSON") from exc
    return get


def connection_record(config):
    transport = config.get("connectionType")
    if transport not in {"mqtt", "mqtt-5", "http-push"}:
        return None
    remote = endpoint(config.get("uri"))
    if not remote:
        return None
    incoming = transport.startswith("mqtt")
    if incoming and remote["scheme"] not in {"mqtt","mqtts","tcp","ssl"} or not incoming and remote["scheme"] not in {"http","https"}:
        return None
    channels = config.get("sources" if incoming else "targets") or []
    if not channels:
        return None
    topics = [str(t) for channel in channels for t in channel.get("addresses" if incoming else "topics", [])]
    write_path = remote["write_path"] or any(c.get("address","").split("?")[0] == "POST:/api/v2/write" for c in channels)
    mapping_definitions = config.get("mappingDefinitions")
    mapping_names = sorted(mapping_definitions) if isinstance(mapping_definitions, dict) else []
    return {"id":config["id"], "protocol":transport, "endpoint":remote,
            "direction":"inbound" if incoming else "outbound", "influx_write_path":write_path,
            "source_address_fingerprints":[digest(str(address)) for channel in channels
                                           for address in channel.get("addresses", [])][:16],
            "target_topic_fingerprints":[digest(t) for t in topics][:16],
            "topic_fingerprints":[digest(t) for t in topics],
            "mapping_fingerprints":[digest(name) for name in mapping_names][:16],
            "has_payload_mapping":any(bool(c.get("payloadMapping")) for c in channels) or bool(config.get("mappingDefinitions")),
            "has_authorization_context":any(bool(c.get("authorizationContext")) for c in channels),
            "failover":bool(config.get("specificConfig", {}).get("serverURIs") or config.get("clientCount", 1) != 1)}


def inspect_ditto(port, get, issues):
    configs = get(port, "/api/2/connections", "ditto")
    if not isinstance(configs, list):
        raise Unavailable("Unsupported connection inventory format")
    records = []
    failed_records = 0
    if len(configs) > 12:
        issues.append("Only the first 12 connections were inspected.")
    for entry in configs[:12]:
        cid = entry.get("id") if isinstance(entry, dict) else entry
        if not isinstance(cid, str) or not SLUG.fullmatch(cid) or cid in (".",".."):
            failed_records += 1
            issues.append("Unsupported connection identifier")
            continue
        base = "/api/2/connections/" + quote(cid, safe="")
        try:
            config = get(port, base, "ditto")
            if config.get("id") != cid:
                raise Unavailable("Connection identity mismatch")
            record = connection_record(config)
            if not record:
                failed_records += 1
                issues.append("Connection configuration unsupported or incomplete")
                continue
            records.append(record)
            start = instant(utc())
            if (record["direction"] == "outbound" and record["endpoint"]["host"] == "host.docker.internal"
                    and record["endpoint"]["port"] == 8095 and any(
                        target.get("address") == "POST:/events" for target in config.get("targets", []))):
                try:
                    writer = get(8095, "/assessment-metadata", "writer")
                    if (writer.get("service") == "ditto-influx-telemetry" and writer.get("host") in ("localhost","127.0.0.1")
                            and type(writer.get("port")) is int and 0 < writer["port"] < 65536):
                        record["writer_influx_host_port"] = writer["port"]
                        if instant(writer.get("last_accepted_at")):
                            record["writer_last_accepted_at"] = writer["last_accepted_at"]
                except (Unavailable, AttributeError):
                    issues.append("Writer metadata unavailable; storage destination unresolved.")
            record["status"] = "unknown"
            state = get(port, base + "/status", "ditto")
            if state.get("connectionId") == cid and state.get("liveStatus") in ("open","closed","failed"):
                record["status"] = state["liveStatus"]
            # Only an event inside this read window can attest to this configuration.
            metrics = get(port, base + "/metrics", "ditto")
            inbound = record["direction"] == "inbound"
            count = metrics.get("connectionMetrics", {}).get("inbound" if inbound else "outbound", {}).get(
                "consumed" if inbound else "dispatched", {}).get("success", {})
            at = instant(count.get("lastMessageAt"))
            if (metrics.get("connectionId") == cid and at and start <= at <= instant(utc())
                    and type(count.get("PT1M")) is int and count["PT1M"] > 0 and not record["failover"]
                    and config == get(port, base, "ditto")):
                record["observed_at"] = at.isoformat()
            elif at:
                record["prior_activity_at"] = at.isoformat()
        except (Unavailable, KeyError, TypeError, AttributeError) as exc:
            failed_records += 1
            issues.append("Connection inspection: " + (str(exc) if isinstance(exc, Unavailable) else "invalid response"))
    incomplete = bool(failed_records or len(configs) > 12)
    return records, {"status": "NO_CONNECTIONS" if not configs else "AVAILABLE",
                     "reason": ("The authenticated connection inventory returned no connections."
                                if not configs else
                                "The connection inventory was readable, but one or more records could not be interpreted completely."
                                if incomplete else "The authenticated connection inventory was fully readable and interpreted."),
                     "total": len(configs), "supported_records": len(records),
                     "failed_records": failed_records, "truncated": len(configs) > 12}


def log_counts(text):
    patterns = {"broker_client_connected":r"New client connected from ",
                "broker_publish_received":r"Received PUBLISH from ",
                "broker_acl_denial":r"Denied (?:PUBLISH|SUBSCRIBE) (?:from|to) ",
                "ditto_thing_modified_event_mentions":r"\bthings:twin/events/(?:modified|attributeModified|featurePropertyModified)\b",
                "influx_write_accepted":r'POST /api/v2/write[^ "]* HTTP/1\.[01]" 204\b'}
    return {key:sum(bool(re.search(pattern,line)) for line in text.splitlines())
            for key,pattern in patterns.items()}


def member_identity(member, run):
    cid = member.get("member_id", "")
    if not isinstance(cid,str) or not HEX_ID.fullmatch(cid):
        return False
    value = run(["docker","inspect","--format","{{.Id}} {{.Image}} {{.State.StartedAt}} {{.State.Running}}",cid])
    return (value["status"] == DISCOVERY_COMPLETE and value["stdout"].split() ==
            [cid,member.get("image_id"),member.get("started_at"),"true"])


def local_engine(run):
    value = os.getenv("DOCKER_HOST")
    if not value or os.getenv("DOCKER_CONTEXT"):
        check = run(["docker","context","inspect","--format","{{.Endpoints.docker.Host}}"])
        value = check.get("stdout","").strip() if check["status"] == DISCOVERY_COMPLETE else ""
    return value.startswith(("npipe:////./pipe/", "unix:///"))


def inspect_member(row, member, run, get):
    cid = member.get("member_id")
    evidence = {"container_id":cid, "version":row["version"], "component_id":row["component_id"],
                "deployment_id":row["deployment_id"], "started":utc(), "issues":[]}
    issues = evidence["issues"]
    product = row["component_id"]
    if cid not in row.get("container_ids", []) or not member_identity(member,run):
        issues.append("Container identity or runtime generation could not be verified.")
        return evidence
    if product == "mosquitto":
        path = member.get("config_path") or "/mosquitto/config/mosquitto.conf"
        res = (run(["docker","exec",cid,"head","-c","32769",path])
               if path in ("/mosquitto/config/mosquitto.conf","/etc/mosquitto/mosquitto.conf")
               else {"status":"Unsupported config location"})
        if res["status"] == DISCOVERY_COMPLETE and len(res["stdout"].encode()) <= 32768:
            directives = mosquitto_config(res["stdout"])
            evidence["mosquitto_file"] = {"source":path, "sha256":digest(res["stdout"]), "directives":directives,
                "limitation":"Directives in this file; effective listener settings, included files and ACL contents unverified."}
            evidence["mosquitto_security"] = mosquitto_security_summary(directives)
            acl_paths = mosquitto_values(res["stdout"], "acl_file")
            if len(acl_paths) == 1 and re.fullmatch(r"/[A-Za-z0-9_.:/-]{1,255}", acl_paths[0]) and ".." not in acl_paths[0].split("/"):
                acl = run(["docker","exec",cid,"head","-c","65537",acl_paths[0]])
                if acl["status"] == DISCOVERY_COMPLETE and len(acl["stdout"].encode()) <= 65536:
                    evidence["mosquitto_security"]["acl_summary"] = mosquitto_acl_summary(acl["stdout"])
                else:
                    issues.append("Referenced Mosquitto ACL file unavailable, unreadable or too large; ACL permissions remain unknown.")
            elif acl_paths:
                issues.append("Mosquitto ACL path could not be inspected safely; ACL permissions remain unknown.")
        else:
            issues.append("Mosquitto config file unavailable, unreadable or too large.")
    recent = datetime.now(timezone.utc) - timedelta(minutes=5)
    since = max(recent, instant(member.get("started_at")) or recent)
    logs = run(["docker","logs","--since",since.isoformat(),"--tail","120",cid])
    if logs["status"] == DISCOVERY_COMPLETE:
        evidence["log_events"] = log_counts((logs.get("stdout") or "") + "\n" + (logs.get("stderr") or ""))
    else:
        issues.append("Recent container logs unavailable.")
    try:
        published = member.get("published_tcp", {})
        if product != "mosquitto" and not local_engine(run):
            raise Unavailable("Local Docker engine binding unverified; API inspection skipped")
        if product in ("ditto","eclipse_ditto") and "gateway" in (member.get("service") or "").lower():
            ports = published.get("8080/tcp",[])
            if len(ports) != 1:
                get = container_api(member,row)
                ports = [8080]
            try:
                evidence["connections"], evidence["connection_inventory"] = inspect_ditto(ports[0], get, issues)
            except Unavailable as exc:
                evidence["connection_inventory"] = {
                    "status": inventory_failure_status(str(exc)),
                    "reason": str(exc),
                }
                raise
        if product == "influxdb":
            ports = published.get("8086/tcp",[])
            if len(ports) != 1:
                get = container_api(member,row)
                ports = [8086]
            evidence["influx_metadata"] = {}
            for resource in ("orgs","buckets"):
                try:
                    data = get(ports[0], "/api/v2/" + resource + "?limit=100", "influxdb")
                    items = data[resource]
                    if not isinstance(items,list):
                        raise Unavailable("Invalid metadata inventory")
                    evidence["influx_metadata"][resource] = [item["id"] for item in items
                        if isinstance(item,dict) and re.fullmatch(r"[0-9a-fA-F]{16}",str(item.get("id","")))]
                except (Unavailable, KeyError, TypeError) as exc:
                    issues.append(resource + ": " + (str(exc) if isinstance(exc,Unavailable) else "invalid metadata"))
    except (Unavailable, TypeError, KeyError, AttributeError) as exc:
        issues.append(str(exc) if isinstance(exc,Unavailable) else "Unsupported API response")
    if not member_identity(member,run):
        return {"issues":["Container changed during inspection. Rediscover deployments."]}
    evidence["finished"] = utc()
    return evidence


def binding_unchanged(member, run=_run_docker):
    if not member_identity(member, run):
        return False
    result = run(["docker", "inspect", "--format", "{{json .NetworkSettings}}", member["member_id"]])
    if result["status"] != DISCOVERY_COMPLETE:
        return False
    try:
        from version_detector import _architecture_metadata
        settings = json.loads(result["stdout"])
        current = _architecture_metadata({"NetworkSettings":settings, "Name":member.get("container_name","")})
        return current["networks"] == member["networks"] and current["published_tcp"] == member["published_tcp"]
    except (TypeError, KeyError, ValueError):
        return False


def collect(row, run=_run_docker, get=read_api):
    return [inspect_member(row,m,run,get) for m in row.get("architecture_metadata",[]) if m.get("member_id")]


def valid(row, evidence, scan):
    start, end, capture = (instant(v) for v in (evidence.get("started"), evidence.get("finished"), scan))
    return (start and end and capture and start <= end <= capture <= instant(utc())
            and instant(utc()) - start <= MAX_AGE
            and evidence.get("container_id") in row["container_ids"]
            and evidence.get("deployment_id") == row["deployment_id"]
            and evidence.get("component_id") == row["component_id"] and evidence.get("version") == row["version"])


def match_connections(source, target, discovery, scan):
    """Bind a Ditto API observation to its peer on the connectivity service networks."""
    incoming = source["component_id"] == "mosquitto"
    ditto, peer = (target, source) if incoming else (source, target)
    if ditto["component_id"] not in ("ditto","eclipse_ditto"):
        return []
    members = [m for m in ditto.get("architecture_metadata",[]) if "connectivity" in (m.get("service") or "")]
    inventory = [m for row in discovery["supported"] + discovery.get("other",[])
                 for m in row.get("architecture_metadata",[])]
    found = []
    for item in ditto.get("inspections",[]):
        if not valid(ditto,item,scan):
            continue
        for connection in item.get("connections",[]):
            remote = connection["endpoint"]
            if (connection["direction"] == "inbound") != incoming:
                continue
            writer_port = connection.get("writer_influx_host_port")
            if not incoming and not connection["influx_write_path"] and not writer_port:
                continue
            host_port = writer_port or (remote["port"] if remote["host"] == "host.docker.internal" else None)
            if host_port:
                service_port = "8086/tcp" if not incoming else None
                owners = [m for m in inventory if any(host_port in ports for key,ports in m.get("published_tcp", {}).items()
                                                       if (key in ("1883/tcp","8883/tcp") if not service_port else key == service_port))]
                if len(owners) == 1 and owners[0].get("member_id") in peer["container_ids"]:
                    at = instant(connection.get("observed_at"))
                    peer_start = instant(owners[0].get("started_at"))
                    observed = bool(not writer_port and at and peer_start and peer_start <= at
                                    and instant(item["started"]) <= at <= instant(item["finished"]))
                    found.append({"connection_id":connection["id"],"protocol":connection["protocol"],
                                  "endpoint":f"{remote['host']}:{remote['port']}",
                                  "via":"Telemetry writer" if writer_port else "Published port",
                                  "source":"Ditto connection and writer metadata" if writer_port else "Ditto connection and Docker port binding",
                                  "timestamp":item["finished"], "observed":observed,
                                  "collected_at":item["finished"],
                                  "connection_status":connection.get("status", "unknown"),
                                  "writer_last_accepted_at":connection.get("writer_last_accepted_at"),
                                  "prior_activity_at":connection.get("prior_activity_at"),
                                  "source_address_fingerprints":connection.get("source_address_fingerprints", []),
                                  "target_topic_fingerprints":connection.get("target_topic_fingerprints", []),
                                  "peer_container_ids":[owners[0]["member_id"]]})
                continue
            if not members:
                continue
            # Every possible connectivity instance must resolve this alias uniquely.
            resolved = []
            for member in members:
                ids = {m.get("member_id") for m in inventory for net in member.get("networks",{})
                       if remote["host"] in m.get("networks",{}).get(net,[])}
                if len(ids) != 1 or not ids.issubset(peer["container_ids"]):
                    break
                resolved.extend(ids)
            else:
                peer_meta = [m for m in peer["architecture_metadata"] if m.get("member_id") in resolved]
                if not peer_meta or any(str(remote["port"])+"/tcp" not in m.get("published_tcp",{})
                                       and not any(remote["port"] in e.get("mosquitto_file",{}).get("directives",{}).get("listener",[])
                                                   for e in peer.get("inspections",[]) if valid(peer,e,scan)
                                                   and e["container_id"] == m["member_id"]) for m in peer_meta):
                    continue
                at = instant(connection.get("observed_at"))
                observed = bool(at and instant(item["started"]) <= at <= instant(item["finished"]) and all(
                    instant(m.get("started_at")) and instant(m["started_at"]) <= at for m in members + peer_meta))
                found.append({"connection_id":connection["id"],"protocol":connection["protocol"],
                              "endpoint":f"{remote['host']}:{remote['port']}",
                              "source":"Ditto GET /api/2/connections/{id}" + (" and /metrics" if observed else ""),
                              "timestamp":connection["observed_at"] if observed else item["finished"],
                              "collected_at":item["finished"],
                              "observed":observed,"connection_status":connection.get("status", "unknown"),
                              "writer_last_accepted_at":connection.get("writer_last_accepted_at"),
                              "prior_activity_at":connection.get("prior_activity_at"),
                              "source_address_fingerprints":connection.get("source_address_fingerprints", []),
                              "target_topic_fingerprints":connection.get("target_topic_fingerprints", []),
                              "peer_container_ids":sorted(set(resolved))})
    return found


def relationship(source, target, discovery, scan, shared_networks=None):
    """Classify one exact deployment pair without promoting connectivity to exploitation."""
    incoming = source.get("component_id") == "mosquitto"
    ditto = target if incoming else source
    records = match_connections(source, target, discovery, scan)
    if any(item.get("observed") for item in records):
        state = OBSERVED_COMMUNICATION
        reason = "Ditto configuration matched this deployment and successful counters were recorded inside the collection window."
    elif records:
        state = VERIFIED_CONFIGURATION
        reason = "Ditto configuration matched this deployment and endpoint; no matching traffic was observed in the collection window."
    else:
        gateway_ids = sorted({
            member.get("member_id") for member in ditto.get("architecture_metadata", [])
            if member.get("member_id") and "gateway" in (member.get("service") or "").lower()
        })
        inspected = [item for item in ditto.get("inspections", []) if valid(ditto, item, scan)]
        inventories = [item.get("connection_inventory", {}) for item in inspected
                       if isinstance(item.get("connection_inventory"), dict)]
        successful_ids = {item.get("container_id") for item in inspected
                          if item.get("connection_inventory", {}).get("status") in {"AVAILABLE", "NO_CONNECTIONS"}}
        complete = bool(gateway_ids and set(gateway_ids).issubset(successful_ids))
        if not complete:
            state = NETWORK_ONLY if shared_networks else UNKNOWN
            failures = list(dict.fromkeys(item.get("reason") for item in inventories if item.get("reason")))
            reason = ("Ditto connection inventory could not be fully read"
                      + ((": " + "; ".join(failures[:3])) if failures else "."))
        else:
            connections = [connection for item in inspected for connection in item.get("connections", [])]
            unresolved_outbound = [
                connection for connection in connections
                if not incoming and connection.get("direction") == "outbound" and (
                    connection.get("influx_write_path")
                    or connection.get("endpoint", {}).get("host") == "host.docker.internal"
                    or connection.get("writer_influx_host_port")
                )
            ]
            incomplete_inventory = any(item.get("failed_records", 0) or item.get("truncated")
                                       for item in inventories)
            if incomplete_inventory:
                state = UNKNOWN
                reason = ("The connection inventory was readable, but one or more configured connections "
                          "could not be interpreted or inspected completely.")
            elif unresolved_outbound:
                state = UNKNOWN
                reason = ("Ditto has a configured outbound path, but its storage destination could not be correlated "
                          "to the exact InfluxDB deployment.")
            else:
                state = NOT_CONFIGURED
                reason = ("The authenticated Ditto inventory contains no matching "
                          + ("inbound MQTT" if incoming else "outbound InfluxDB") +
                          " connection for the exact deployment pair.")
    return {
        "state": state,
        "reason": reason,
        "meaning": RELATIONSHIP_STATE_MEANINGS[state],
        "records": records,
        "inventory": plain_inventory(ditto, scan),
    }


def plain_inventory(ditto, scan):
    result = []
    for item in ditto.get("inspections", []):
        if not valid(ditto, item, scan) or "connection_inventory" not in item:
            continue
        inventory = item["connection_inventory"]
        result.append({
            "container_id": item.get("container_id"),
            "status": inventory.get("status", "DISCOVERY_FAILED"),
            "reason": inventory.get("reason"),
            "total_connections": inventory.get("total"),
            "supported_records": inventory.get("supported_records"),
            "failed_records": inventory.get("failed_records", 0),
            "truncated": bool(inventory.get("truncated")),
            "collected_at": item.get("finished"),
        })
    return result
