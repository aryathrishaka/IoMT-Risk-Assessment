"""Run one reversible Mosquitto-to-Ditto normal data-flow observation.

The test uses one existing vulnerable-lab MQTT connection, one existing
isolated test Thing field, and one non-retained message. It temporarily adds
the minimum broker ACL and Ditto policy permissions required for the test,
then restores every changed state in a cleanup block.
"""

from __future__ import annotations

import base64
import copy
import getpass
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote, unquote, urlsplit
import uuid

import requests
from requests.auth import HTTPBasicAuth


ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "http://localhost:8080"
THING_ID = "iomt:device1"
THING_URL = f"{BASE_URL}/api/2/things/{THING_ID}"
POLICY_URL = f"{BASE_URL}/api/2/policies/{THING_ID}"
CONNECTION_ID = "709e3efe-3c62-4e41-9538-dc5316c43efd"
ALTERNATE_CONNECTION_ID = "10d920b9-6860-47d8-a66b-1a2039391904"
CONNECTION_URL = f"{BASE_URL}/api/2/connections/{CONNECTION_ID}"
MQTT_TOPIC = "iomt/vuln-test"
BROKER_CONTAINER = "mosquitto-vuln-lab"
FIELD_NAME = "temperature"
FIELD_PATH = "/attributes/temperature"
IDLE_SECONDS = 5
OBSERVATION_TIMEOUT_SECONDS = 20


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run_command(
    args: list[str],
    *,
    input_bytes: bytes | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        args,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )


def docker_output(*args: str) -> str:
    completed = run_command(["docker", *args])
    if completed.returncode != 0:
        raise RuntimeError(f"Docker command failed: docker {' '.join(args)}")
    return completed.stdout.decode("utf-8", errors="replace")


def docker_json(*args: str):
    return json.loads(docker_output(*args))


def read_thing(session: requests.Session) -> dict:
    response = session.get(THING_URL, timeout=20)
    response.raise_for_status()
    return response.json()


def read_field(session: requests.Session) -> object:
    thing = read_thing(session)
    return thing.get("attributes", {}).get(FIELD_NAME)


def read_connection(session: requests.Session) -> dict:
    response = session.get(CONNECTION_URL, timeout=20)
    response.raise_for_status()
    return response.json()


def read_connection_status(session: requests.Session) -> dict:
    response = session.get(f"{CONNECTION_URL}/status", timeout=20)
    response.raise_for_status()
    return response.json()


def read_connection_metrics(session: requests.Session) -> dict:
    response = session.get(f"{CONNECTION_URL}/metrics", timeout=20)
    response.raise_for_status()
    return response.json()


def read_connection_logs(session: requests.Session) -> dict:
    response = session.get(f"{CONNECTION_URL}/logs", timeout=20)
    response.raise_for_status()
    return response.json()


def encode_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack("!H", len(encoded)) + encoded


def encode_remaining_length(length: int) -> bytes:
    encoded = bytearray()
    while True:
        value = length % 128
        length //= 128
        if length:
            value |= 0x80
        encoded.append(value)
        if not length:
            return bytes(encoded)


def mqtt_packet(packet_type: int, flags: int, payload: bytes) -> bytes:
    return (
        bytes([(packet_type << 4) | flags])
        + encode_remaining_length(len(payload))
        + payload
    )


def read_mqtt_packet(sock: socket.socket) -> tuple[int, bytes]:
    first = sock.recv(1)
    if len(first) != 1:
        raise RuntimeError("MQTT connection closed before a response.")

    multiplier = 1
    remaining = 0
    while True:
        raw = sock.recv(1)
        if len(raw) != 1:
            raise RuntimeError("MQTT connection closed in the packet length.")
        byte = raw[0]
        remaining += (byte & 0x7F) * multiplier
        if not byte & 0x80:
            break
        multiplier *= 128

    body = bytearray()
    while len(body) < remaining:
        chunk = sock.recv(remaining - len(body))
        if not chunk:
            raise RuntimeError("MQTT connection closed in the packet body.")
        body.extend(chunk)

    return first[0], bytes(body)


def mqtt_publish_qos1(
    host: str,
    port: int,
    username: str,
    password: str,
    topic: str,
    payload: bytes,
    client_id: str | None = None,
) -> dict:
    client_id = client_id or f"iomt-df-publisher-{uuid.uuid4().hex[:12]}"
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.settimeout(10)
        variable_header = (
            encode_string("MQTT")
            + bytes([4])
            + bytes([0xC2])
            + struct.pack("!H", 30)
        )
        connect_payload = (
            encode_string(client_id)
            + encode_string(username)
            + encode_string(password)
        )
        sock.sendall(mqtt_packet(1, 0, variable_header + connect_payload))
        packet_type, connack = read_mqtt_packet(sock)
        if packet_type >> 4 != 2 or len(connack) != 2 or connack[1] != 0:
            raise RuntimeError("MQTT CONNECT was not accepted.")

        packet_id = int(uuid.uuid4().int % 65535) + 1
        publish_payload = (
            encode_string(topic)
            + struct.pack("!H", packet_id)
            + payload
        )
        publish_started = utc_now()
        sock.sendall(mqtt_packet(3, 2, publish_payload))

        while True:
            packet_type, body = read_mqtt_packet(sock)
            if packet_type >> 4 == 4:
                if len(body) != 2:
                    raise RuntimeError("Malformed PUBACK.")
                acknowledged_id = struct.unpack("!H", body)[0]
                if acknowledged_id != packet_id:
                    raise RuntimeError("PUBACK packet identifier mismatch.")
                break

        sock.sendall(b"\xE0\x00")
        return {
            "client_id": client_id,
            "packet_id": packet_id,
            "publish_started_utc": publish_started,
            "publish_sent_utc": publish_started,
            "puback_received_utc": utc_now(),
            "qos": 1,
            "retained": False,
        }


def wait_for_port(host: str, port: int, timeout_seconds: int = 20) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def extract_log_timestamp(line: str) -> str | None:
    match = re.match(r"^(\d{4}-\d{2}-\d{2}T\S+)", line)
    return match.group(1) if match else None


def correlate_broker_logs(lines, since_utc, topic, client_id):
    """Return only broker observations from this run and publisher."""

    since = datetime.fromisoformat(since_utc.replace("Z", "+00:00"))
    received = []
    delivered = []
    for line in lines:
        timestamp = extract_log_timestamp(line)
        if timestamp is None or topic not in line:
            continue
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if parsed < since:
            continue
        if "Received PUBLISH from" in line and client_id in line:
            received.append(line)
        if "Sending PUBLISH to" in line:
            delivered.append(line)
    return {
        "received": received,
        "delivered": delivered,
    }


def _metric_value(snapshot, *path):
    value = snapshot
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value if isinstance(value, (int, float)) else None


def _metric_delta(before, after, *path):
    before_value = _metric_value(before or {}, *path)
    after_value = _metric_value(after or {}, *path)
    if before_value is None or after_value is None:
        return None
    return after_value - before_value


def evaluate_ditto_receipt(
    metrics_before,
    metrics_after,
    topic,
    expected_marker,
    observed_marker,
):
    """Require relevant inbound delivery counters and matching readback."""

    overall_consumed = _metric_delta(
        metrics_before,
        metrics_after,
        "connectionMetrics",
        "inbound",
        "consumed",
        "success",
        "PT1M",
    )
    overall_mapped = _metric_delta(
        metrics_before,
        metrics_after,
        "connectionMetrics",
        "inbound",
        "mapped",
        "success",
        "PT1M",
    )
    address_metrics_before = (
        (metrics_before or {})
        .get("sourceMetrics", {})
        .get("addressMetrics")
    )
    topic_consumed = _metric_delta(
        metrics_before,
        metrics_after,
        "sourceMetrics",
        "addressMetrics",
        topic,
        "consumed",
        "success",
        "PT1M",
    )
    topic_mapped = _metric_delta(
        metrics_before,
        metrics_after,
        "sourceMetrics",
        "addressMetrics",
        topic,
        "mapped",
        "success",
        "PT1M",
    )
    relevant_counters = (
        overall_consumed is not None
        and overall_consumed > 0
        and overall_mapped is not None
        and overall_mapped > 0
    )
    if isinstance(address_metrics_before, dict) and topic in address_metrics_before:
        relevant_counters = (
            relevant_counters
            and topic_consumed is not None
            and topic_consumed > 0
            and topic_mapped is not None
            and topic_mapped > 0
        )
    marker_match = (
        observed_marker is not None
        and observed_marker == expected_marker
    )
    return {
        "verified": relevant_counters and marker_match,
        "relevant_inbound_counters_increased": relevant_counters,
        "marker_match": marker_match,
        "overall_consumed_delta": overall_consumed,
        "overall_mapped_delta": overall_mapped,
        "topic_consumed_delta": topic_consumed,
        "topic_mapped_delta": topic_mapped,
    }


def restrict_local_permissions(path):
    """Restrict a backup path to the current local user."""

    if os.name != "nt":
        mode = 0o700 if Path(path).is_dir() else 0o600
        os.chmod(path, mode)
        return True

    domain = os.environ.get("USERDOMAIN")
    username = os.environ.get("USERNAME") or getpass.getuser()
    account = f"{domain}\\{username}" if domain else username
    permission = (
        f"{account}:(OI)(CI)F"
        if Path(path).is_dir()
        else f"{account}:F"
    )
    completed = run_command(
        [
            "icacls",
            str(path),
            "/inheritance:r",
            "/grant:r",
            permission,
            "/Q",
        ]
    )
    return completed.returncode == 0


def write_private_text(path, value):
    """Write a local backup and verify that its ACL was restricted."""

    Path(path).write_text(value, encoding="utf-8")
    return restrict_local_permissions(path)


def summarize_experiment_and_cleanup(experiment_outcome, cleanup_checks):
    """Keep experiment validity and required restoration outcomes separate."""

    required = {
        key: value
        for key, value in cleanup_checks.items()
        if value is not None
    }
    cleanup_verified = all(value is True for value in required.values())
    cleanup_outcome = (
        "NOT_REQUIRED"
        if not required
        else "VERIFIED"
        if cleanup_verified
        else "FAILED"
    )
    if experiment_outcome == "VALIDATED" and cleanup_verified:
        overall = "COMPLETED"
        exit_code = 0
    elif experiment_outcome == "VALIDATED":
        overall = "CLEANUP_FAILED"
        exit_code = 1
    else:
        overall = "EXPERIMENT_FAILED"
        exit_code = 1
    return {
        "result": overall,
        "experiment_outcome": experiment_outcome,
        "cleanup_outcome": cleanup_outcome,
        "exit_code": exit_code,
    }


def restore_connection_to_closed(
    session,
    original_connection,
    timeout_seconds=OBSERVATION_TIMEOUT_SECONDS,
    status_reader=read_connection_status,
):
    """Restore a connection even when its update response times out."""

    restored = copy.deepcopy(original_connection)
    restored["connectionStatus"] = "closed"
    request_error = None
    try:
        session.put(
            CONNECTION_URL,
            json=restored,
            timeout=20,
        )
    except requests.RequestException as exc:
        request_error = f"{type(exc).__name__}: {exc}"

    for _ in range(timeout_seconds):
        try:
            status = status_reader(session)
        except Exception as exc:
            request_error = (
                request_error
                or f"Status check failed: {type(exc).__name__}: {exc}"
            )
            time.sleep(1)
            continue
        if status.get("liveStatus") == "closed":
            return {
                "verified": True,
                "request_error": request_error,
            }
        time.sleep(1)
    return {
        "verified": False,
        "request_error": request_error,
    }


def main() -> int:
    run_id = (
        "mosquitto-ditto-dataflow-"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    )
    evidence_path = ROOT / "output" / "evidence_runs" / f"{run_id}.json"
    backup_root = (
        Path(os.environ["LOCALAPPDATA"])
        / "IoMT-Lab-Backups"
        / "MosquittoDittoDataFlow"
        / run_id
    )
    backup_root.mkdir(parents=True, exist_ok=False)
    backup_directory_permissions_verified = restrict_local_permissions(
        backup_root
    )
    if not backup_directory_permissions_verified:
        print("Unable to restrict the local backup directory permissions.")
        return 2

    ordinary_password = getpass.getpass(
        "Enter the current ordinary ditto nginx password: "
    )
    if not ordinary_password:
        print("The ordinary ditto password cannot be empty.")
        return 2

    gateway_env = docker_json(
        "inspect",
        "docker-gateway-1",
        "--format",
        "{{json .Config.Env}}",
    )
    devops_entry = next(
        (
            item
            for item in gateway_env
            if item.startswith("DEVOPS_PASSWORD=")
        ),
        None,
    )
    if not devops_entry:
        print("The local DevOps credential is unavailable.")
        return 2
    devops_password = devops_entry.split("=", 1)[1]

    connection_source = json.loads(
        (ROOT / "vulnerable-ditto-connection.json").read_text(encoding="utf-8")
    )
    broker_uri = urlsplit(connection_source["uri"])
    if not broker_uri.username or broker_uri.password is None:
        print("The existing broker credential source is unavailable.")
        return 2
    mqtt_username = unquote(broker_uri.username)
    mqtt_password = unquote(broker_uri.password)

    ordinary = requests.Session()
    ordinary.trust_env = False
    ordinary.auth = HTTPBasicAuth("ditto", ordinary_password)

    devops = requests.Session()
    devops.trust_env = False
    devops.auth = HTTPBasicAuth("devops", devops_password)

    original_broker_state = docker_output(
        "inspect", BROKER_CONTAINER, "--format", "{{.State.Status}}"
    ).strip()
    marker = (
        "LAB-DF-"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid.uuid4().hex[:8]
    )
    mqtt_client_id = f"iomt-df-publisher-{uuid.uuid4().hex[:12]}"

    original_thing: dict | None = None
    original_policy: dict | None = None
    original_policy_write_body: dict | None = None
    original_connection: dict | None = None
    original_connection_status: dict | None = None
    original_acl: bytes | None = None
    original_field: object = None
    initial_field_present = False
    idle_value_present = False
    idle_value: object = None
    idle_unchanged = False
    policy_modified = False
    policy_change_attempted = False
    connection_modified = False
    connection_change_attempted = False
    acl_modified = False
    field_write_attempted = False
    publication_attempted = False
    publication_attempted_utc: str | None = None
    backup_files_permissions_verified = True

    experiment_outcome = "FAILED"
    cleanup_outcome = "NOT_RUN"
    result = "FAILED"
    failure: str | None = None
    stages = {
        "publication_attempted": "UNVERIFIED",
        "broker_acceptance": "UNVERIFIED",
        "ditto_receipt": "UNVERIFIED",
        "ditto_processing": "UNVERIFIED",
        "thing_field_mutation": "UNVERIFIED",
    }
    timings: dict[str, object] = {}
    metrics_before: dict | None = None
    metrics_after: dict | None = None
    connection_logs_after: dict | None = None
    broker_receive_lines: list[str] = []
    broker_delivery_lines: list[str] = []
    observed_value: object = None
    observed_value_present = False
    restored_field_value: object = None
    restore_field_verified = False
    restore_policy_verified = False
    restore_connection_verified = False
    restore_acl_verified = False
    broker_final_state: str | None = None
    metrics_receipt: dict | None = None
    acl_write_rule_verified = False

    try:
        thing_response = ordinary.get(THING_URL, timeout=20)
        thing_response.raise_for_status()
        original_thing = thing_response.json()
        if original_thing.get("thingId") != THING_ID:
            raise RuntimeError("The Things API returned an unexpected Thing.")
        if original_thing.get("policyId") != THING_ID:
            raise RuntimeError("The target Thing policy is unexpected.")
        attributes = original_thing.get("attributes") or {}
        initial_field_present = FIELD_NAME in attributes
        if not initial_field_present:
            raise RuntimeError("The intended Thing field is missing.")
        original_field = attributes[FIELD_NAME]

        policy_response = ordinary.get(POLICY_URL, timeout=20)
        policy_response.raise_for_status()
        original_policy = policy_response.json()
        original_policy_write_body = {
            "policyId": original_policy.get("policyId"),
            "entries": original_policy.get("entries") or {},
        }
        if "imports" in original_policy:
            original_policy_write_body["imports"] = original_policy["imports"]
        entries = original_policy.get("entries") or {}
        default_entry = entries.get("DEFAULT") or {}
        subjects = default_entry.get("subjects") or {}
        if set(subjects) != {"nginx:ditto"}:
            raise RuntimeError("The target policy is not isolated to nginx:ditto.")

        timings["idle_started_utc"] = utc_now()
        time.sleep(IDLE_SECONDS)
        idle_attributes = read_thing(ordinary).get("attributes") or {}
        idle_value_present = FIELD_NAME in idle_attributes
        idle_value = idle_attributes.get(FIELD_NAME)
        timings["idle_finished_utc"] = utc_now()
        idle_unchanged = (
            idle_value_present
            and type(idle_value) is type(original_field)
            and idle_value == original_field
        )
        if not idle_unchanged:
            raise RuntimeError("The target Thing field changed during idle control.")

        original_connection = read_connection(devops)
        original_connection_status = read_connection_status(devops)
        if original_connection.get("connectionStatus") != "closed":
            raise RuntimeError("The selected connection was not initially closed.")
        if original_connection_status.get("liveStatus") != "closed":
            raise RuntimeError("The selected connection was not initially offline.")
        alternate_status = devops.get(
            f"{BASE_URL}/api/2/connections/{ALTERNATE_CONNECTION_ID}/status",
            timeout=20,
        )
        alternate_status.raise_for_status()
        if alternate_status.json().get("liveStatus") == "open":
            raise RuntimeError("The alternate vulnerable-broker route is active.")

        sources = original_connection.get("sources") or []
        if len(sources) != 1 or MQTT_TOPIC not in sources[0].get("addresses", []):
            raise RuntimeError("The selected connection source topic is unexpected.")

        backup_documents = {
            "connection-original.json": original_connection,
            "connection-status-original.json": original_connection_status,
            "thing-original.json": original_thing,
            "policy-original.json": original_policy,
        }
        for name, document in backup_documents.items():
            backup_files_permissions_verified = (
                write_private_text(
                    backup_root / name,
                    json.dumps(document, indent=2),
                )
                and backup_files_permissions_verified
            )
        if not backup_files_permissions_verified:
            raise RuntimeError(
                "Unable to restrict backup file permissions."
            )

        acl_copy = run_command(
            [
                "docker",
                "cp",
                f"{BROKER_CONTAINER}:/mosquitto/config/aclfile",
                str(backup_root / "aclfile.original"),
            ]
        )
        if acl_copy.returncode != 0:
            raise RuntimeError("Unable to back up the broker ACL.")
        if not restrict_local_permissions(backup_root / "aclfile.original"):
            raise RuntimeError(
                "Unable to restrict the ACL backup permissions."
            )
        original_acl = (backup_root / "aclfile.original").read_bytes()
        if b"user sensoruser" not in original_acl:
            raise RuntimeError("The expected MQTT user is absent from the ACL.")
        if b"read iomt/vuln-test" not in original_acl:
            raise RuntimeError("The expected MQTT read ACL is absent.")

        temporary_acl = original_acl
        if not temporary_acl.endswith((b"\n", b"\r")):
            temporary_acl += b"\n"
        temporary_acl += b"write " + MQTT_TOPIC.encode("ascii") + b"\n"
        staged_acl = backup_root / "aclfile.test"
        staged_acl.write_bytes(temporary_acl)
        if not restrict_local_permissions(staged_acl):
            raise RuntimeError("Unable to restrict staged ACL permissions.")

        copy_result = run_command(
            [
                "docker",
                "cp",
                str(staged_acl),
                f"{BROKER_CONTAINER}:/mosquitto/config/aclfile",
            ]
        )
        if copy_result.returncode != 0:
            raise RuntimeError("Unable to stage the temporary MQTT ACL.")
        acl_modified = True
        active_acl_text = docker_output(
            "exec",
            BROKER_CONTAINER,
            "cat",
            "/mosquitto/config/aclfile",
        )
        acl_write_rule_verified = (
            f"write {MQTT_TOPIC}" in active_acl_text.splitlines()
        )
        if not acl_write_rule_verified:
            raise RuntimeError("The temporary MQTT write ACL is not active.")

        restart_result = run_command(["docker", "restart", BROKER_CONTAINER])
        if restart_result.returncode != 0 or not wait_for_port("127.0.0.1", 1884):
            raise RuntimeError("The vulnerable broker did not restart cleanly.")

        probe_env = os.environ.copy()
        probe_env.update(
            {
                "MQTT_PROBE_HOST": "127.0.0.1",
                "MQTT_PROBE_PORT": "1884",
                "MQTT_PROBE_TOPIC": MQTT_TOPIC,
                "MQTT_PROBE_USERNAME": mqtt_username,
                "MQTT_PROBE_PASSWORD": mqtt_password,
            }
        )
        auth_probe = run_command(
            [sys.executable, str(ROOT / "tools" / "mqtt_auth_probe.py")],
            env=probe_env,
        )
        if auth_probe.returncode != 0:
            raise RuntimeError("The authorized MQTT publisher could not connect.")

        modified_policy = copy.deepcopy(original_policy_write_body)
        modified_policy["entries"]["DEFAULT"]["subjects"][
            "ditto:inbound-auth-subject"
        ] = {"type": "generated"}
        policy_change_attempted = True
        policy_update = ordinary.put(POLICY_URL, json=modified_policy, timeout=20)
        if policy_update.status_code not in (200, 204):
            raise RuntimeError("Unable to stage the temporary Ditto policy grant.")
        policy_modified = True

        modified_connection = copy.deepcopy(original_connection)
        broker_host = broker_uri.hostname
        broker_port = broker_uri.port or 1883
        modified_connection["uri"] = (
            "tcp://"
            + quote(mqtt_username, safe="")
            + ":"
            + quote(mqtt_password, safe="")
            + f"@{broker_host}:{broker_port}"
        )
        modified_connection["connectionStatus"] = "open"
        connection_change_attempted = True
        connection_update = devops.put(
            CONNECTION_URL,
            json=modified_connection,
            timeout=20,
        )
        if connection_update.status_code not in (200, 204):
            raise RuntimeError("Unable to activate the selected connection.")
        connection_modified = True

        live_open = False
        status_after_activation: dict = {}
        for _ in range(OBSERVATION_TIMEOUT_SECONDS):
            status_after_activation = read_connection_status(devops)
            if status_after_activation.get("liveStatus") == "open":
                live_open = True
                break
            time.sleep(1)
        if not live_open:
            raise RuntimeError("The selected connection did not become live.")

        metrics_before = read_connection_metrics(devops)

        message = json.loads(
            (ROOT / "ditto-message.json").read_text(encoding="utf-8-sig")
        )
        message["path"] = FIELD_PATH
        message["value"] = marker
        publish_payload = json.dumps(message, separators=(",", ":")).encode(
            "utf-8"
        )

        publication_attempted = True
        publication_attempted_utc = utc_now()
        timings["publication_invoked_utc"] = publication_attempted_utc
        stages["publication_attempted"] = "YES"
        broker_log_window_start = utc_now()
        publish_result = mqtt_publish_qos1(
            "127.0.0.1",
            1884,
            mqtt_username,
            mqtt_password,
            MQTT_TOPIC,
            publish_payload,
            client_id=mqtt_client_id,
        )
        timings.update(publish_result)
        stages["publication_attempted"] = "VERIFIED"
        stages["broker_acceptance"] = "VERIFIED_BY_PUBACK"

        deadline = time.monotonic() + OBSERVATION_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            current_attributes = read_thing(ordinary).get("attributes") or {}
            observed_value_present = FIELD_NAME in current_attributes
            observed_value = current_attributes.get(FIELD_NAME)
            if observed_value_present and observed_value == marker:
                timings["field_changed_observed_utc"] = utc_now()
                stages["thing_field_mutation"] = "VERIFIED"
                stages["ditto_processing"] = "VERIFIED_BY_THING_MUTATION"
                field_write_attempted = True
                break
            time.sleep(1)

        time.sleep(1)
        broker_logs = docker_output(
            "logs",
            "--timestamps",
            "--since",
            broker_log_window_start,
            BROKER_CONTAINER,
        ).splitlines()
        correlated_logs = correlate_broker_logs(
            broker_logs,
            broker_log_window_start,
            MQTT_TOPIC,
            mqtt_client_id,
        )
        broker_receive_lines = correlated_logs["received"]
        broker_delivery_lines = correlated_logs["delivered"]

        if broker_receive_lines:
            timings["broker_received_log_utc"] = extract_log_timestamp(
                broker_receive_lines[-1]
            )
            stages["broker_acceptance"] = "VERIFIED_BY_PUBACK_AND_BROKER_LOG"
        if broker_delivery_lines:
            timings["broker_delivery_log_utc"] = extract_log_timestamp(
                broker_delivery_lines[-1]
            )

        metrics_after = read_connection_metrics(devops)
        connection_logs_after = read_connection_logs(devops)
        metrics_receipt = evaluate_ditto_receipt(
            metrics_before,
            metrics_after,
            MQTT_TOPIC,
            marker,
            observed_value if observed_value_present else None,
        )
        if metrics_receipt["verified"]:
            stages["ditto_receipt"] = (
                "VERIFIED_BY_INBOUND_COUNTERS_AND_THING_MARKER"
            )

        if stages["thing_field_mutation"] != "VERIFIED":
            raise RuntimeError("The test marker was not observed through the API.")

        experiment_outcome = (
            "VALIDATED"
            if (
                stages["publication_attempted"] == "VERIFIED"
                and stages["broker_acceptance"]
                in (
                    "VERIFIED_BY_PUBACK",
                    "VERIFIED_BY_PUBACK_AND_BROKER_LOG",
                )
                and stages["ditto_receipt"]
                == "VERIFIED_BY_INBOUND_COUNTERS_AND_THING_MARKER"
                and stages["ditto_processing"]
                == "VERIFIED_BY_THING_MUTATION"
            )
            else "FAILED"
        )
    except Exception as exc:
        failure = f"{type(exc).__name__}: {exc}"
    finally:
        cleanup_failure = None
        try:
            current_value = read_field(ordinary)
            if current_value == marker:
                field_write_attempted = True
        except Exception:
            pass

        connection_restore_required = (
            connection_change_attempted or connection_modified
        )
        if connection_restore_required and original_connection is not None:
            try:
                restore_result = restore_connection_to_closed(
                    devops,
                    original_connection,
                )
                restore_connection_verified = restore_result["verified"]
                if not restore_connection_verified:
                    cleanup_failure = (
                        "Connection restoration was unverified: "
                        f"{restore_result['request_error'] or 'status not closed'}"
                    )
            except Exception as exc:
                cleanup_failure = (
                    "Connection restoration failed: "
                    f"{type(exc).__name__}: {exc}"
                )
                restore_connection_verified = False

        connection_closed_before_field = (
            not connection_restore_required
            or restore_connection_verified
        )

        if connection_closed_before_field:
            try:
                current_value = read_field(ordinary)
                if current_value == marker:
                    field_write_attempted = True
            except Exception:
                pass

        if (
            field_write_attempted
            and original_field is not None
            and connection_closed_before_field
        ):
            try:
                try:
                    ordinary.put(
                        f"{THING_URL}/attributes/{FIELD_NAME}",
                        json=original_field,
                        timeout=20,
                    )
                except requests.RequestException:
                    # Verify the value even if the response timed out.
                    pass
                restored_field_value = read_field(ordinary)
                restore_field_verified = (
                    restored_field_value == original_field
                )
            except Exception as exc:
                cleanup_failure = (
                    "Field restoration failed: "
                    f"{type(exc).__name__}: {exc}"
                )
                restore_field_verified = False
        elif field_write_attempted:
            cleanup_failure = (
                "Field restoration was not attempted because the test "
                "connection was not verified closed."
            )
            restore_field_verified = False

        if policy_change_attempted and original_policy is not None:
            try:
                try:
                    ordinary.put(
                        POLICY_URL,
                        json=original_policy_write_body,
                        timeout=20,
                    )
                except requests.RequestException:
                    # The API may have applied the restoration before timeout.
                    pass
                restored_policy = ordinary.get(POLICY_URL, timeout=20)
                restore_policy_verified = (
                    restored_policy.status_code == 200
                    and restored_policy.json().get("entries", {})
                    == original_policy.get("entries", {})
                )
            except Exception as exc:
                cleanup_failure = (
                    "Policy restoration failed: "
                    f"{type(exc).__name__}: {exc}"
                )
                restore_policy_verified = False

        if acl_modified and original_acl is not None:
            try:
                restore_copy = run_command(
                    [
                        "docker",
                        "cp",
                        str(backup_root / "aclfile.original"),
                        f"{BROKER_CONTAINER}:/mosquitto/config/aclfile",
                    ]
                )
                restore_restart = run_command(
                    ["docker", "restart", BROKER_CONTAINER]
                )
                wait_for_port("127.0.0.1", 1884)
                exported_acl = backup_root / "aclfile.restored"
                export_result = run_command(
                    [
                        "docker",
                        "cp",
                        f"{BROKER_CONTAINER}:/mosquitto/config/aclfile",
                        str(exported_acl),
                    ]
                )
                if export_result.returncode == 0:
                    restrict_local_permissions(exported_acl)
                restore_acl_verified = (
                    restore_copy.returncode == 0
                    and restore_restart.returncode == 0
                    and export_result.returncode == 0
                    and exported_acl.read_bytes() == original_acl
                )
            except Exception as exc:
                cleanup_failure = (
                    "ACL restoration failed: "
                    f"{type(exc).__name__}: {exc}"
                )
                restore_acl_verified = False

        if original_broker_state == "running":
            run_command(["docker", "start", BROKER_CONTAINER])
        elif original_broker_state == "exited":
            run_command(["docker", "stop", BROKER_CONTAINER])

        try:
            broker_final_state = docker_output(
                "inspect",
                BROKER_CONTAINER,
                "--format",
                "{{.State.Status}}",
            ).strip()
        except Exception:
            broker_final_state = "UNAVAILABLE"
        broker_state_restored = broker_final_state == original_broker_state

        cleanup_checks = {
            "field": (
                restore_field_verified
                if field_write_attempted and original_field is not None
                else None
            ),
            "policy": (
                restore_policy_verified
                if policy_change_attempted and original_policy is not None
                else None
            ),
            "connection": (
                restore_connection_verified
                if connection_restore_required
                else None
            ),
            "broker_acl": (
                restore_acl_verified if acl_modified else None
            ),
            "broker_state": broker_state_restored,
        }
        outcomes = summarize_experiment_and_cleanup(
            experiment_outcome,
            cleanup_checks,
        )
        result = outcomes["result"]
        cleanup_outcome = outcomes["cleanup_outcome"]

        evidence = {
            "schema_version": "1.0",
            "run_id": run_id,
            "collected_at_utc": utc_now(),
            "result": result,
            "failure": failure,
            "cleanup_failure": cleanup_failure,
            "experiment_outcome": experiment_outcome,
            "cleanup_outcome": cleanup_outcome,
            "scope": "One controlled normal Mosquitto-to-Ditto data-flow message",
            "baseline": {
                "assessment": (
                    "output/ebsr_assessments/"
                    "ebsr-assessment-20261115T151044933456Z-"
                    "vresearch-mosquitto-2026-11-10-v3.json"
                ),
                "scenario_id": "RESEARCH-12546-DITTO",
                "source_deployment_id": "mosquitto-vuln-lab",
            },
            "test_route": {
                "connection_id": CONNECTION_ID,
                "alternate_connection_id": ALTERNATE_CONNECTION_ID,
                "mqtt_source_topic": MQTT_TOPIC,
                "thing_id": THING_ID,
                "field_path": FIELD_PATH,
                "payload_topic": message.get("topic")
                if "message" in locals()
                else None,
                "payload_mapping": "default Ditto Protocol payload mapper",
            },
            "isolation": {
                "policy_id": THING_ID,
                "policy_subject": "nginx:ditto",
                "policy_isolated": True,
            },
            "preconditions": {
                "initial_field_present": initial_field_present,
                "idle_value_present": idle_value_present,
                "idle_unchanged": idle_unchanged,
                "idle_duration_seconds": IDLE_SECONDS,
                "broker_publisher_authenticated": auth_probe.returncode == 0
                if "auth_probe" in locals()
                else False,
                "temporary_acl_write_rule_verified": acl_write_rule_verified,
                "connection_live": live_open if "live_open" in locals() else False,
                "backup_permissions_verified": (
                    backup_directory_permissions_verified
                    and backup_files_permissions_verified
                ),
            },
            "values": {
                "before": original_field,
                "idle": idle_value,
                "marker": marker,
                "observed_after": observed_value,
                "after_observed_present": observed_value_present,
                "restored": restored_field_value,
            },
            "timings": timings,
            "stage_results": stages,
            "broker_evidence": {
                "log_window_start_utc": broker_log_window_start
                if "broker_log_window_start" in locals()
                else None,
                "mqtt_client_id": mqtt_client_id,
                "received_publish_log_count": len(broker_receive_lines),
                "delivery_log_count": len(broker_delivery_lines),
            },
            "ditto_evidence": {
                "metrics_before": metrics_before,
                "metrics_after": metrics_after,
                "receipt_check": metrics_receipt,
                "connection_logs_after": connection_logs_after,
            },
            "cleanup": {
                "outcome": cleanup_outcome,
                "required_checks": cleanup_checks,
                "connection_closed_before_field_restore": (
                    connection_closed_before_field
                ),
                "field_restore_verified": restore_field_verified,
                "policy_restore_verified": restore_policy_verified
                if policy_change_attempted
                else "NO_CHANGE",
                "connection_restore_verified": restore_connection_verified
                if connection_restore_required
                else "NO_CHANGE",
                "acl_restore_verified": restore_acl_verified
                if acl_modified
                else "NO_CHANGE",
                "broker_initial_state": original_broker_state,
                "broker_final_state": broker_final_state,
                "broker_state_restored": broker_state_restored,
                "secure_backup_directory": str(backup_root),
                "backup_permissions_verified": (
                    backup_directory_permissions_verified
                    and backup_files_permissions_verified
                ),
            },
            "changes": {
                "message_publication_attempted": publication_attempted,
                "message_puback_received": (
                    "puback_received_utc" in timings
                ),
                "message_retained": (
                    (publish_result or {}).get("retained")
                    if "publish_result" in locals()
                    else None
                ),
                "policy_modified_temporarily": policy_modified,
                "policy_change_attempted": policy_change_attempted,
                "connection_modified_temporarily": connection_modified,
                "connection_change_attempted": connection_change_attempted,
                "broker_acl_modified_temporarily": acl_modified,
                "things_created": False,
                "policies_created": False,
                "influxdb_involved": False,
            },
            "assessment_boundary": (
                "This observation establishes only the tested normal data flow "
                "and receiver processing for this deployment. It does not "
                "establish vulnerability exploitation, adverse C/I/A impact, "
                "attack feasibility, or propagation to InfluxDB."
            ),
        }

        evidence_text = json.dumps(evidence, indent=2)
        credentials_recorded = any(
            secret and secret in evidence_text
            for secret in (
                ordinary_password,
                devops_password,
                mqtt_password,
            )
        )
        password_hashes_recorded = bool(re.search(
            r"\$(?:apr1|2[aby]|6)\$",
            evidence_text,
        ))
        authorization_headers_recorded = bool(re.search(
            r"(?i)authorization[^\r\n]{0,100}basic\s+[A-Za-z0-9+/=]{8,}",
            evidence_text,
        ))
        evidence["credential_handling"] = {
            "credentials_recorded": credentials_recorded,
            "password_hashes_recorded": password_hashes_recorded,
            "authorization_headers_recorded": (
                authorization_headers_recorded
            ),
        }
        evidence_text = json.dumps(evidence, indent=2)
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(evidence_text, encoding="utf-8")

        ordinary_password = ""
        devops_password = ""
        mqtt_password = ""
        ordinary.close()
        devops.close()

        print(f"RESULT={result}")
        print(f"EXPERIMENT_OUTCOME={experiment_outcome}")
        print(f"CLEANUP_OUTCOME={cleanup_outcome}")
        print(f"HTTP_FIELD_BEFORE={original_field}")
        print(f"HTTP_FIELD_AFTER={observed_value}")
        print(f"HTTP_FIELD_RESTORED={restored_field_value}")
        print(f"BROKER_ACCEPTANCE={stages['broker_acceptance']}")
        print(f"DITTO_RECEIPT={stages['ditto_receipt']}")
        print(f"PROCESSING={stages['ditto_processing']}")
        print(f"FIELD_RESTORED={restore_field_verified}")
        print(f"POLICY_RESTORED={restore_policy_verified}")
        print(f"CONNECTION_RESTORED={restore_connection_verified}")
        print(f"ACL_RESTORED={restore_acl_verified}")
        print(f"BROKER_FINAL_STATE={evidence['cleanup']['broker_final_state']}")
        print(f"EVIDENCE={evidence_path}")

    return outcomes["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
