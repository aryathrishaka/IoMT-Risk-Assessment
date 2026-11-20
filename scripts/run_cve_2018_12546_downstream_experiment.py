"""Run the CVE-2018-12546 Mosquitto -> Ditto -> InfluxDB experiment.

The experiment compares one vulnerable and one control retained-message path.
Each arm uses a temporary broker, distinct MQTT identities, an isolated Ditto
Thing/policy, and a temporary Ditto event-to-InfluxDB writer.

The tested policy is: after publisher write permission is revoked and that
revocation is independently enforced, a previously retained command must not
update the isolated Thing or create corresponding telemetry.
"""

from __future__ import annotations

import argparse
import copy
import csv
from datetime import datetime, timezone
import getpass
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import time
from typing import Any
import uuid
from urllib.parse import quote

import requests
from requests.auth import HTTPBasicAuth

from run_cve_2018_12546_experiment import (
    CONTROL,
    VULNERABLE,
    DockerClient,
    MqttConnection,
    atomic_write_text,
    broker_configuration,
    broker_logs,
    cleanup_assessment,
    find_reload_log,
    host_port,
    initial_acl,
    legacy_password_line,
    reload_broker,
    restrict_local_permissions,
    revoked_acl,
    utc_now,
    wait_for_tcp,
    write_private_text,
)
from run_ditto_influx_validation import (
    BASE_URL,
    CONNECTION_TEMPLATE,
    INFLUX_URL,
    PRIVATE_ROOT,
    WRITER_HOST,
    WRITER_PORT,
    WRITER_SCRIPT,
)


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_ROOT = ROOT / "output" / "evidence_runs"
DOCKER_NETWORK = "docker_default"
MQTT_VERSION = "3.1.1"
DEFAULT_BUCKET = "iomt-ditto-influx-test-cd1c965d2a"
DEFAULT_ORG = "IoMT-Lab"
BASELINE_TEMPERATURE = 37.0
BASELINE_MARKER = "BASELINE"
NORMAL_TEMPERATURE = 41.25
RETAINED_TEMPERATURE = 42.75
POST_CONTROL_TEMPERATURE = 40.5
THING_FIELD = "temperature"
MARKER_FIELD = "runMarker"
OBSERVATION_TIMEOUT_SECONDS = 20
CONNECTION_ID = "709e3efe-3c62-4e41-9538-dc5316c43efd"
EXPERIMENT_LABEL = "io.iomt.experiment"

POLICY_TEXT = (
    "After publisher write permission is revoked and enforcement is verified, "
    "its previously retained test command must not update the isolated "
    "downstream Thing or create a corresponding telemetry record."
)


def request_checked(
    session: requests.Session,
    method: str,
    url: str,
    *,
    expected: tuple[int, ...],
    **kwargs,
) -> requests.Response:
    response = session.request(method, url, timeout=20, **kwargs)
    if response.status_code not in expected:
        raise RuntimeError(f"{method} {url} returned HTTP {response.status_code}.")
    return response


def redact_connection(connection: dict[str, Any]) -> dict[str, Any]:
    redacted = copy.deepcopy(connection)
    uri = redacted.get("uri")
    if isinstance(uri, str):
        from urllib.parse import urlsplit, urlunsplit

        parsed = urlsplit(uri)
        redacted["uri"] = urlunsplit(
            (
                parsed.scheme,
                f"{parsed.hostname or ''}"
                + (f":{parsed.port}" if parsed.port else ""),
                parsed.path,
                "",
                "",
            )
        )
    return redacted


def current_connection_snapshot(
    devops: requests.Session,
) -> dict[str, Any]:
    response = request_checked(
        devops,
        "GET",
        f"{BASE_URL}/api/2/connections",
        expected=(200,),
    )
    value = response.json()
    if isinstance(value, dict):
        return {
            connection_id: redact_connection(connection)
            for connection_id, connection in value.items()
        }
    return {
        connection.get("id", "UNKNOWN"): redact_connection(connection)
        for connection in value
    }


def read_devops_password(docker: DockerClient) -> str:
    environment = docker.json(
        "inspect",
        "docker-gateway-1",
        "--format",
        "{{json .Config.Env}}",
    )
    for item in environment:
        if item.startswith("DEVOPS_PASSWORD="):
            return item.split("=", 1)[1]
    raise RuntimeError("The local DevOps credential is unavailable.")


def policy_document(policy_id: str) -> dict[str, Any]:
    return {
        "policyId": policy_id,
        "entries": {
            "DEFAULT": {
                "subjects": {
                    "nginx:ditto": {"type": "generated"},
                    "ditto:inbound-auth-subject": {"type": "generated"},
                    "ditto:outbound-auth-subject": {"type": "generated"},
                },
                "resources": {
                    "thing:/": {
                        "grant": ["READ", "WRITE"],
                        "revoke": [],
                    },
                    "policy:/": {
                        "grant": ["READ", "WRITE"],
                        "revoke": [],
                    },
                },
                "importable": "implicit",
            }
        },
    }


def baseline_thing(thing_id: str, policy_id: str) -> dict[str, Any]:
    return {
        "thingId": thing_id,
        "policyId": policy_id,
        "attributes": {
            THING_FIELD: BASELINE_TEMPERATURE,
            MARKER_FIELD: BASELINE_MARKER,
        },
    }


def ditto_command_payload(
    thing_id: str,
    temperature: float,
    marker: str,
) -> dict[str, Any]:
    return {
        "topic": (
            f"{thing_id.replace(':', '/', 1)}"
            "/things/twin/commands/modify"
        ),
        "headers": {},
        "path": "/attributes",
        "value": {
            THING_FIELD: temperature,
            MARKER_FIELD: marker,
        },
    }


def thing_has_values(
    thing: dict[str, Any] | None,
    temperature: float,
    marker: str,
) -> bool:
    attributes = (thing or {}).get("attributes") or {}
    return (
        attributes.get(THING_FIELD) == temperature
        and attributes.get(MARKER_FIELD) == marker
    )


def writer_event_matches(
    state: dict[str, Any] | None,
    thing_id: str,
    temperature: float,
    marker: str,
) -> bool:
    return bool(
        state
        and state.get("result") == "WRITTEN"
        and state.get("thing_id") == thing_id
        and state.get("temperature") == temperature
        and state.get("run_marker") == marker
        and state.get("influx_http_status") == 204
    )


def wait_for_thing(
    ditto: requests.Session,
    thing_id: str,
    temperature: float,
    marker: str,
    timeout_seconds: int = OBSERVATION_TIMEOUT_SECONDS,
) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout_seconds
    last = None
    while time.monotonic() < deadline:
        response = request_checked(
            ditto,
            "GET",
            f"{BASE_URL}/api/2/things/{thing_id}",
            expected=(200,),
        )
        last = response.json()
        if thing_has_values(last, temperature, marker):
            return last
        time.sleep(0.25)
    return last


def wait_for_connection_status(
    devops: requests.Session,
    connection_id: str,
    desired: str,
    timeout_seconds: int = OBSERVATION_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        response = request_checked(
            devops,
            "GET",
            f"{BASE_URL}/api/2/connections/{connection_id}/status",
            expected=(200,),
        )
        last = response.json()
        if last.get("liveStatus") == desired:
            return last
        time.sleep(0.25)
    raise RuntimeError(
        f"Connection {connection_id} did not reach {desired}; "
        f"last status was {last.get('liveStatus')}."
    )


def set_connection_status(
    devops: requests.Session,
    connection_id: str,
    connection_config: dict[str, Any],
    status: str,
) -> dict[str, Any]:
    changed = copy.deepcopy(connection_config)
    changed["connectionStatus"] = status
    request_checked(
        devops,
        "PUT",
        f"{BASE_URL}/api/2/connections/{connection_id}",
        expected=(200, 204),
        json=changed,
    )
    status_result = wait_for_connection_status(
        devops,
        connection_id,
        status,
    )
    return {
        "status": status,
        "verified": status_result.get("liveStatus") == status,
        "details": status_result,
    }


def read_metrics(
    devops: requests.Session,
    connection_id: str,
) -> dict[str, Any]:
    response = request_checked(
        devops,
        "GET",
        f"{BASE_URL}/api/2/connections/{connection_id}/metrics",
        expected=(200,),
    )
    return response.json()


def metric_value(snapshot: dict[str, Any], *path: str) -> float | None:
    value: Any = snapshot
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value if isinstance(value, (int, float)) else None


def metric_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    paths = {
        "overall_consumed": (
            "connectionMetrics",
            "inbound",
            "consumed",
            "success",
            "PT1M",
        ),
        "overall_mapped": (
            "connectionMetrics",
            "inbound",
            "mapped",
            "success",
            "PT1M",
        ),
    }
    result = {}
    for name, path in paths.items():
        before_value = metric_value(before, *path)
        after_value = metric_value(after, *path)
        result[name] = (
            after_value - before_value
            if before_value is not None and after_value is not None
            else None
        )
    return result


def retained_broker_logs(
    lines: list[str],
    *,
    since_utc: str,
    topic: str,
) -> list[str]:
    since = datetime.fromisoformat(since_utc.replace("Z", "+00:00"))
    matches = []
    for line in lines:
        timestamp_match = line[:32]
        try:
            timestamp = datetime.fromisoformat(
                timestamp_match.split(" ", 1)[0].replace("Z", "+00:00")
            )
        except ValueError:
            continue
        if timestamp < since or topic not in line:
            continue
        if "Sending PUBLISH to" in line:
            matches.append(line)
    return matches


def start_temp_broker(
    docker: DockerClient,
    *,
    arm: dict[str, Any],
    container_name: str,
    network_alias: str,
    config_directory: Path,
    credentials: dict[str, str],
    topic: str,
    experiment_id: str,
) -> dict[str, Any]:
    config_directory.mkdir(parents=True, exist_ok=False)
    if not restrict_local_permissions(config_directory):
        raise RuntimeError("Unable to restrict the temporary broker directory.")
    password_text = "\n".join(
        legacy_password_line(user, password, os.urandom(12))
        for user, password in credentials.items()
    )
    if not write_private_text(config_directory / "passwd", password_text + "\n"):
        raise RuntimeError("Unable to create the temporary password file.")
    if not write_private_text(
        config_directory / "mosquitto.conf",
        broker_configuration(arm["check_retain_source"]),
    ):
        raise RuntimeError("Unable to create the temporary broker config.")
    if not write_private_text(
        config_directory / "aclfile",
        initial_acl(topic),
    ):
        raise RuntimeError("Unable to create the temporary ACL.")

    mount = (
        "type=bind,source="
        + config_directory.resolve().as_posix()
        + ",target=/mosquitto/config,readonly"
    )
    docker.run(
        "run",
        "--detach",
        "--name",
        container_name,
        "--network",
        DOCKER_NETWORK,
        "--network-alias",
        network_alias,
        "--publish",
        "127.0.0.1::1883",
        "--label",
        f"{EXPERIMENT_LABEL}={experiment_id}",
        "--label",
        f"io.iomt.arm={arm['arm']}",
        "--mount",
        mount,
        arm["image_id"],
        timeout=60,
    )
    port = host_port(docker, container_name, 1883)
    if not wait_for_tcp("127.0.0.1", port):
        raise RuntimeError("The temporary broker did not open its MQTT port.")
    inspected = docker.json("inspect", container_name)[0]
    version_output = docker.run(
        "exec",
        container_name,
        "/usr/sbin/mosquitto",
        "-h",
        allow_failure=True,
    )
    combined = (version_output.stdout + version_output.stderr).decode(
        "utf-8", errors="replace"
    )
    match = re.search(r"mosquitto version ([0-9][^\s]*)", combined)
    return {
        "container_name": container_name,
        "container_id": inspected.get("Id"),
        "image_id": inspected.get("Image"),
        "image_reference": arm["image_reference"],
        "network": DOCKER_NETWORK,
        "network_alias": network_alias,
        "host": "127.0.0.1",
        "host_port": port,
        "started_utc": inspected.get("State", {}).get("StartedAt"),
        "runtime_version": match.group(1) if match else None,
        "configuration": broker_configuration(arm["check_retain_source"]),
    }


def start_writer(
    *,
    runtime_directory: Path,
    thing_id: str,
    bucket: str,
    org: str,
    write_token: str,
) -> tuple[subprocess.Popen, Path, Path, Path, dict[str, Any]]:
    runtime_directory.mkdir(parents=True, exist_ok=True)
    if not restrict_local_permissions(runtime_directory):
        raise RuntimeError("Unable to restrict the writer runtime directory.")
    config_path = runtime_directory / "writer-config.json"
    state_path = runtime_directory / "writer-state.json"
    log_path = runtime_directory / "writer.log"
    error_path = runtime_directory / "writer-error.log"
    if state_path.exists():
        state_path.unlink()
    config = {
        "listen_host": "0.0.0.0",
        "listen_port": WRITER_PORT,
        "influx_url": INFLUX_URL,
        "influx_org": org,
        "influx_bucket": bucket,
        "expected_thing_id": thing_id,
        "state_file": str(state_path),
    }
    config_path.write_text(
        json.dumps(config, indent=2) + "\n",
        encoding="utf-8",
    )
    with log_path.open("wb") as output, error_path.open("wb") as error:
        process = subprocess.Popen(
            [
                sys.executable,
                str(WRITER_SCRIPT),
                "--config",
                str(config_path),
                "--token-stdin",
            ],
            stdin=subprocess.PIPE,
            stdout=output,
            stderr=error,
        )
        assert process.stdin is not None
        process.stdin.write((write_token + "\n").encode("utf-8"))
        process.stdin.flush()
        process.stdin.close()
    return process, config_path, state_path, log_path, config


def wait_for_writer(timeout_seconds: int = 20) -> bool:
    session = requests.Session()
    session.trust_env = False
    deadline = time.monotonic() + timeout_seconds
    try:
        while time.monotonic() < deadline:
            try:
                response = session.get(
                    f"http://127.0.0.1:{WRITER_PORT}/health",
                    timeout=1,
                )
                if response.status_code == 200:
                    return True
            except requests.RequestException:
                pass
            time.sleep(0.25)
        return False
    finally:
        session.close()


def writer_port_is_free() -> bool:
    try:
        with socket.create_connection(
            ("127.0.0.1", WRITER_PORT),
            timeout=0.5,
        ):
            return False
    except OSError:
        return True


def downstream_preflight(
    *,
    ditto: requests.Session,
    devops: requests.Session,
) -> dict[str, Any]:
    thing_response = ditto.get(
        f"{BASE_URL}/api/2/things/iomt:device1?fields=thingId",
        timeout=20,
    )
    connection_response = devops.get(
        f"{BASE_URL}/api/2/connections/{CONNECTION_ID}",
        timeout=20,
    )
    influx_session = requests.Session()
    influx_session.trust_env = False
    try:
        health_response = influx_session.get(
            f"{INFLUX_URL}/health",
            timeout=10,
        )
    finally:
        influx_session.close()
    writer_free = writer_port_is_free()
    checks = {
        "ordinary_ditto_access": thing_response.status_code in (200, 404),
        "devops_connection_access": connection_response.status_code == 200,
        "influx_health": health_response.status_code == 200,
        "writer_port_available": writer_free,
    }
    return {
        "checks": checks,
        "verified": all(checks.values()),
        "ordinary_ditto_http": thing_response.status_code,
        "devops_connection_http": connection_response.status_code,
        "influx_health_http": health_response.status_code,
        "writer_port": WRITER_PORT,
    }


def stop_writer(process: subprocess.Popen) -> bool:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    return process.poll() is not None


def read_writer_state(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def wait_for_writer_event(
    state_path: Path,
    thing_id: str,
    temperature: float,
    marker: str,
    timeout_seconds: int = OBSERVATION_TIMEOUT_SECONDS,
) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout_seconds
    last = None
    while time.monotonic() < deadline:
        last = read_writer_state(state_path)
        if writer_event_matches(last, thing_id, temperature, marker):
            return last
        time.sleep(0.25)
    return last


def query_influx(
    *,
    read_token: str,
    org: str,
    bucket: str,
    thing_id: str,
    marker: str,
    timeout_seconds: int = 20,
) -> dict[str, Any]:
    if not read_token:
        return {
            "status": "PENDING_USER_CONFIRMATION",
            "reason": "No bucket-scoped read credential was supplied.",
            "row": None,
        }
    session = requests.Session()
    session.trust_env = False
    query = (
        f'from(bucket: "{bucket}")\n'
        "  |> range(start: -24h)\n"
        '  |> filter(fn: (r) => r._measurement == "ditto_thing_event")\n'
        '  |> filter(fn: (r) => r._field == "temperature")\n'
        f'  |> filter(fn: (r) => r.thing_id == "{thing_id}")\n'
        f'  |> filter(fn: (r) => r.run_marker == "{marker}")\n'
        "  |> last()\n"
        '  |> keep(columns: ["_time", "_value", "thing_id", "run_marker"])'
    )
    try:
        deadline = time.monotonic() + timeout_seconds
        last_status = None
        while time.monotonic() < deadline:
            response = session.post(
                f"{INFLUX_URL}/api/v2/query",
                params={"org": org},
                headers={
                    "Authorization": f"Token {read_token}",
                    "Content-Type": "application/vnd.flux",
                    "Accept": "application/csv",
                },
                data=query.encode("utf-8"),
                timeout=20,
            )
            last_status = response.status_code
            if response.status_code != 200:
                return {
                    "status": "QUERY_FAILED",
                    "http_status": response.status_code,
                    "row": None,
                }
            lines = [
                line
                for line in response.text.splitlines()
                if not line.startswith("#")
            ]
            for row in csv.DictReader(io.StringIO("\n".join(lines))):
                if row.get("_value"):
                    return {
                        "status": "CONFIRMED",
                        "http_status": response.status_code,
                        "row": row,
                    }
            time.sleep(0.5)
        return {
            "status": "ROW_NOT_FOUND",
            "http_status": last_status,
            "row": None,
        }
    finally:
        session.close()


def clean_private_runtime(runtime_directory: Path) -> bool:
    resolved = runtime_directory.resolve()
    expected = PRIVATE_ROOT.resolve()
    is_run_root = resolved.parent == expected
    is_arm_directory = (
        resolved.parent.parent == expected
        and resolved.parent.name.startswith(
            "cve-2018-12546-downstream-"
        )
        and resolved.name in ("vulnerable", "control")
    )
    if not is_run_root and not is_arm_directory:
        return False
    if resolved.exists():
        import shutil

        shutil.rmtree(resolved)
    return not resolved.exists()


def cleanup_broker(
    docker: DockerClient,
    container_name: str,
    experiment_id: str,
) -> bool:
    inspected = docker.run(
        "inspect",
        container_name,
        "--format",
        f'{{{{ index .Config.Labels "{EXPERIMENT_LABEL}" }}}}',
        allow_failure=True,
    )
    if inspected.returncode == 0:
        label = inspected.stdout.decode("utf-8", errors="replace").strip()
        if label != experiment_id:
            return False
        docker.run("rm", "--force", container_name, allow_failure=True)
    remaining = docker.run("container", "inspect", container_name, allow_failure=True)
    return remaining.returncode != 0


def delete_ditto_resource(
    session: requests.Session,
    url: str,
) -> bool:
    response = session.delete(url, timeout=20)
    if response.status_code not in (200, 204, 404):
        return False
    check = session.get(url, timeout=20)
    return check.status_code == 404


def normal_path_verified(
    normal_thing: dict[str, Any] | None,
    normal_writer_state: dict[str, Any] | None,
    normal_influx: dict[str, Any],
    thing_id: str,
    marker: str,
) -> bool:
    return (
        thing_has_values(normal_thing, NORMAL_TEMPERATURE, marker)
        and writer_event_matches(
            normal_writer_state,
            thing_id,
            NORMAL_TEMPERATURE,
            marker,
        )
        and normal_influx.get("status") in (
            "CONFIRMED",
            "PENDING_USER_CONFIRMATION",
        )
    )


def classify_downstream_outcome(
    *,
    arm_name: str,
    normal_path_ok: bool,
    revoked_before_retained_delivery: bool,
    retained_was_established: bool,
    malicious_thing_changed: bool,
    malicious_writer_event: bool,
    malicious_influx_row: bool,
    post_control_thing_changed: bool,
    post_control_writer_event: bool,
) -> dict[str, Any]:
    policy_effect_observed = (
        malicious_thing_changed
        or malicious_writer_event
        or malicious_influx_row
    )
    prerequisites_met = (
        normal_path_ok
        and revoked_before_retained_delivery
        and retained_was_established
    )
    post_control_ok = (
        post_control_thing_changed and post_control_writer_event
    )
    if not prerequisites_met:
        outcome = "INCONCLUSIVE"
    elif arm_name == "vulnerable":
        outcome = (
            "POLICY_VIOLATION_OBSERVED"
            if policy_effect_observed
            else "UNEXPECTED_WITHHELD"
        )
    elif policy_effect_observed:
        outcome = "UNEXPECTED_CONTROL_POLICY_VIOLATION"
    elif post_control_ok:
        outcome = "POLICY_HELD"
    else:
        outcome = "INCONCLUSIVE_POST_CONTROL_FAILED"
    return {
        "outcome": outcome,
        "prerequisites_met": prerequisites_met,
        "malicious_thing_changed": malicious_thing_changed,
        "malicious_writer_event": malicious_writer_event,
        "malicious_influx_row": malicious_influx_row,
        "post_revocation_control_verified": post_control_ok,
        "policy_violation": policy_effect_observed,
    }


def run_arm(
    *,
    arm: dict[str, Any],
    docker: DockerClient,
    ditto: requests.Session,
    devops: requests.Session,
    original_mqtt_connection: dict[str, Any],
    version: str,
    suffix: str,
    bucket: str,
    org: str,
    write_token: str,
    read_token: str,
    runtime_root: Path,
) -> dict[str, Any]:
    arm_name = arm["arm"]
    run_token = secrets.token_hex(5)
    thing_id = f"iomt:cve12546-{arm_name}-{suffix}-{run_token}"
    policy_id = f"iomt:cve12546-{arm_name}-policy-{suffix}-{run_token}"
    mqtt_connection_id = str(uuid.uuid4())
    event_connection_id = str(uuid.uuid4())
    container_name = f"iomt-cve12546-down-{arm_name}-{run_token}"
    network_alias = f"iomt-cve12546-down-{arm_name}-{suffix}"
    topic = f"iomt/experiments/cve-2018-12546/downstream/{suffix}/{arm_name}"
    normal_marker = f"CVE12546-NORMAL-{arm_name.upper()}-{run_token}"
    retained_marker = f"CVE12546-REVOKED-RETAINED-{arm_name.upper()}-{run_token}"
    post_marker = f"CVE12546-POST-CONTROL-{arm_name.upper()}-{run_token}"
    arm_runtime = runtime_root / arm_name
    arm_runtime.mkdir(parents=True, exist_ok=False)
    if not restrict_local_permissions(arm_runtime):
        raise RuntimeError("Unable to restrict the arm runtime directory.")

    credentials = {
        "experiment-publisher": secrets.token_urlsafe(24),
        "experiment-subscriber": secrets.token_urlsafe(24),
        "experiment-health-publisher": secrets.token_urlsafe(24),
    }
    evidence: dict[str, Any] = {
        "arm": arm_name,
        "policy": POLICY_TEXT,
        "expected": (
            "Retained command delivered after enforced revocation changes "
            "the Thing and creates telemetry."
            if arm_name == "vulnerable"
            else "Retained command is withheld; an authorized post-control "
            "message still updates the Thing and telemetry."
        ),
        "deployment": {},
        "thing_id": thing_id,
        "policy_id": policy_id,
        "mqtt_topic": topic,
        "normal": {},
        "retained": {},
        "post_control": {},
        "cleanup": {},
    }
    writer_process: subprocess.Popen | None = None
    event_connection_created = False
    mqtt_connection_created = False
    thing_created = False
    policy_created = False
    broker_created = False
    writer_state_path: Path | None = None
    event_connection_config: dict[str, Any] | None = None
    mqtt_connection_config: dict[str, Any] | None = None

    try:
        evidence["deployment"] = start_temp_broker(
            docker,
            arm=arm,
            container_name=container_name,
            network_alias=network_alias,
            config_directory=arm_runtime / "broker",
            credentials=credentials,
            topic=topic,
            experiment_id=f"experiment-2-{suffix}-{arm_name}",
        )
        broker_created = True
        if (
            evidence["deployment"]["runtime_version"]
            != arm["expected_version"]
        ):
            raise RuntimeError("The temporary broker runtime version is unexpected.")
        manifest = docker.json("image", "inspect", arm["image_id"])[0]
        if manifest.get("Id") != arm["image_id"]:
            raise RuntimeError("The exact requested image ID is unavailable.")

        request_checked(
            ditto,
            "PUT",
            f"{BASE_URL}/api/2/policies/{policy_id}",
            expected=(200, 201, 204),
            json=policy_document(policy_id),
        )
        policy_created = True
        request_checked(
            ditto,
            "PUT",
            f"{BASE_URL}/api/2/things/{thing_id}",
            expected=(200, 201, 204),
            json=baseline_thing(thing_id, policy_id),
        )
        thing_created = True

        event_connection_config = json.loads(
            CONNECTION_TEMPLATE.read_text(encoding="utf-8")
        )
        event_connection_config["id"] = event_connection_id
        event_connection_config["connectionStatus"] = "closed"
        event_connection_config["uri"] = (
            f"http://{WRITER_HOST}:{WRITER_PORT}"
        )
        request_checked(
            devops,
            "PUT",
            f"{BASE_URL}/api/2/connections/{event_connection_id}",
            expected=(200, 201, 204),
            json=event_connection_config,
        )
        event_connection_created = True

        mqtt_connection_config = copy.deepcopy(original_mqtt_connection)
        mqtt_connection_config["id"] = mqtt_connection_id
        mqtt_connection_config["name"] = f"CVE-2018-12546 {arm_name} temporary"
        mqtt_connection_config["connectionStatus"] = "closed"
        mqtt_connection_config["uri"] = (
            "tcp://experiment-subscriber:"
            + quote(credentials["experiment-subscriber"], safe="")
            + f"@{network_alias}:1883"
        )
        if mqtt_connection_config.get("sources"):
            mqtt_connection_config["sources"][0]["addresses"] = [topic]
        request_checked(
            devops,
            "PUT",
            f"{BASE_URL}/api/2/connections/{mqtt_connection_id}",
            expected=(200, 201, 204),
            json=mqtt_connection_config,
        )
        mqtt_connection_created = True
        evidence["configuration"] = {
            "mqtt_connection": redact_connection(mqtt_connection_config),
            "event_connection": copy.deepcopy(event_connection_config),
            "broker_acl_initial": initial_acl(topic),
            "broker_acl_revoked": revoked_acl(topic),
            "policy": policy_document(policy_id),
            "writer_template_sha256": hashlib.sha256(
                CONNECTION_TEMPLATE.read_bytes()
            ).hexdigest(),
        }

        writer_process, _, writer_state_path, writer_log, writer_config = start_writer(
            runtime_directory=arm_runtime / "writer",
            thing_id=thing_id,
            bucket=bucket,
            org=org,
            write_token=write_token,
        )
        if not wait_for_writer():
            raise RuntimeError("The InfluxDB event writer did not become ready.")
        open_event = set_connection_status(
            devops,
            event_connection_id,
            event_connection_config,
            "open",
        )
        open_mqtt = set_connection_status(
            devops,
            mqtt_connection_id,
            mqtt_connection_config,
            "open",
        )

        normal_things_before = request_checked(
            ditto,
            "GET",
            f"{BASE_URL}/api/2/things/{thing_id}",
            expected=(200,),
        ).json()
        idle_started = utc_now()
        time.sleep(4)
        normal_things_idle = request_checked(
            ditto,
            "GET",
            f"{BASE_URL}/api/2/things/{thing_id}",
            expected=(200,),
        ).json()
        idle_finished = utc_now()
        idle_stable = (
            normal_things_before.get("attributes")
            == normal_things_idle.get("attributes")
        )

        normal_publish = MqttConnection(
            "127.0.0.1",
            evidence["deployment"]["host_port"],
            "experiment-health-publisher",
            credentials["experiment-health-publisher"],
            f"cve12546-{arm_name}-normal-publisher-{secrets.token_hex(4)}",
        )
        normal_publish.connect()
        normal_pub_result = normal_publish.publish(
            topic,
            json.dumps(
                ditto_command_payload(
                    thing_id,
                    NORMAL_TEMPERATURE,
                    normal_marker,
                ),
                separators=(",", ":"),
            ),
            retained=False,
            qos=1,
        )
        normal_publish.close()
        normal_thing = wait_for_thing(
            ditto,
            thing_id,
            NORMAL_TEMPERATURE,
            normal_marker,
        )
        normal_writer = wait_for_writer_event(
            writer_state_path,
            thing_id,
            NORMAL_TEMPERATURE,
            normal_marker,
        )
        normal_influx = query_influx(
            read_token=read_token,
            org=org,
            bucket=bucket,
            thing_id=thing_id,
            marker=normal_marker,
        )
        normal_ok = (
            idle_stable
            and normal_pub_result["puback_received"]
            and thing_has_values(normal_thing, NORMAL_TEMPERATURE, normal_marker)
            and writer_event_matches(
                normal_writer,
                thing_id,
                NORMAL_TEMPERATURE,
                normal_marker,
            )
            and normal_influx["status"]
            in ("CONFIRMED", "PENDING_USER_CONFIRMATION")
        )
        evidence["normal"] = {
            "thing_before": normal_things_before,
            "idle_window": {
                "started_utc": idle_started,
                "finished_utc": idle_finished,
                "thing_stable": idle_stable,
            },
            "marker": normal_marker,
            "temperature": NORMAL_TEMPERATURE,
            "publish": normal_pub_result,
            "thing_after": normal_thing,
            "writer_event": normal_writer,
            "influx_readback": normal_influx,
            "open_event_connection": open_event,
            "open_mqtt_connection": open_mqtt,
            "verified": normal_ok,
        }
        if not normal_ok:
            raise RuntimeError("The normal end-to-end prerequisite failed.")

        close_mqtt = set_connection_status(
            devops,
            mqtt_connection_id,
            mqtt_connection_config,
            "closed",
        )
        close_event = set_connection_status(
            devops,
            event_connection_id,
            event_connection_config,
            "closed",
        )
        writer_stopped_after_normal = (
            stop_writer(writer_process) if writer_process is not None else True
        )
        writer_process = None
        evidence["normal"]["closed_before_retained_stage"] = {
            "mqtt_connection": close_mqtt,
            "event_connection": close_event,
            "writer_stopped": writer_stopped_after_normal,
        }
        if not (
            close_mqtt["verified"]
            and close_event["verified"]
            and writer_stopped_after_normal
        ):
            raise RuntimeError("The downstream path was not closed before the test.")

        request_checked(
            ditto,
            "PUT",
            f"{BASE_URL}/api/2/things/{thing_id}/attributes",
            expected=(200, 201, 204),
            json={
                THING_FIELD: BASELINE_TEMPERATURE,
                MARKER_FIELD: BASELINE_MARKER,
            },
        )
        reset_thing = request_checked(
            ditto,
            "GET",
            f"{BASE_URL}/api/2/things/{thing_id}",
            expected=(200,),
        ).json()
        if not thing_has_values(
            reset_thing,
            BASELINE_TEMPERATURE,
            BASELINE_MARKER,
        ):
            raise RuntimeError("The isolated Thing was not reset to baseline.")

        source_publisher = MqttConnection(
            "127.0.0.1",
            evidence["deployment"]["host_port"],
            "experiment-publisher",
            credentials["experiment-publisher"],
            f"cve12546-{arm_name}-retained-source-{secrets.token_hex(4)}",
        )
        source_publisher.connect()
        retained_pub_result = source_publisher.publish(
            topic,
            json.dumps(
                ditto_command_payload(
                    thing_id,
                    RETAINED_TEMPERATURE,
                    retained_marker,
                ),
                separators=(",", ":"),
            ),
            retained=True,
            qos=1,
        )
        source_publisher.close()

        retained_checker = MqttConnection(
            "127.0.0.1",
            evidence["deployment"]["host_port"],
            "experiment-subscriber",
            credentials["experiment-subscriber"],
            f"cve12546-{arm_name}-retained-check-{secrets.token_hex(4)}",
        )
        retained_checker.connect()
        retained_checker.subscribe(topic)
        retained_messages = retained_checker.collect_for(
            4,
            after_marker=json.dumps(
                ditto_command_payload(
                    thing_id,
                    RETAINED_TEMPERATURE,
                    retained_marker,
                ),
                separators=(",", ":"),
            ),
        )
        retained_checker.close()
        retained_established = any(
            retained_marker in message["payload"] for message in retained_messages
        )
        evidence["retained"]["stored_message_check"] = {
            "marker": retained_marker,
            "temperature": RETAINED_TEMPERATURE,
            "publish": retained_pub_result,
            "raw_subscriber_messages": retained_messages,
            "retained_message_established": retained_established,
        }
        if not retained_established:
            raise RuntimeError("The retained source command was not stored.")

        atomic_write_text(
            arm_runtime / "broker" / "aclfile",
            revoked_acl(topic),
        )
        reload_started = utc_now()
        reload = reload_broker(
            docker,
            container_name,
            wait_for_reload=lambda since: find_reload_log(
                broker_logs(docker, container_name, since_utc=since),
                since,
            ),
        )
        if not reload["reload_log_observed"]:
            raise RuntimeError("The broker did not report an ACL reload.")

        observer = MqttConnection(
            "127.0.0.1",
            evidence["deployment"]["host_port"],
            "experiment-subscriber",
            credentials["experiment-subscriber"],
            f"cve12546-{arm_name}-revocation-observer-{secrets.token_hex(4)}",
        )
        observer.connect()
        observer.subscribe(topic)
        observer.collect_for(4, after_marker=retained_marker)
        revoked_publisher_id = (
            f"cve12546-{arm_name}-revoked-publisher-{secrets.token_hex(4)}"
        )
        revoked_publisher = MqttConnection(
            "127.0.0.1",
            evidence["deployment"]["host_port"],
            "experiment-publisher",
            credentials["experiment-publisher"],
            revoked_publisher_id,
        )
        revoked_publisher.connect()
        revoked_attempt = revoked_publisher.publish(
            topic,
            json.dumps(
                ditto_command_payload(
                    thing_id,
                    RETAINED_TEMPERATURE + 1,
                    retained_marker + "-DENIED-PROBE",
                ),
                separators=(",", ":"),
            ),
            retained=True,
            qos=1,
        )
        revoked_publisher.close()
        time.sleep(0.5)
        denied_probe_messages = observer.collect_for(4)
        observer.close()
        denial_logs = broker_logs(
            docker,
            container_name,
            since_utc=revoked_attempt["publication_attempted_utc"],
        )
        denial_lines = [
            line
            for line in denial_logs
            if revoked_publisher_id in line
            and topic in line
            and "Denied PUBLISH" in line
        ]
        revocation_enforced = (
            bool(denial_lines)
            and not any(
                "-DENIED-PROBE" in message["payload"]
                for message in denied_probe_messages
            )
        )
        evidence["retained"]["revocation"] = {
            "reload_started_utc": reload_started,
            "reload": reload,
            "attempt": revoked_attempt,
            "broker_denial_log_lines": denial_lines,
            "probe_messages": denied_probe_messages,
            "enforced": revocation_enforced,
            "puback_not_treated_as_authorization": True,
        }
        if not revocation_enforced:
            raise RuntimeError("Publisher revocation was not independently enforced.")

        # Recreate the writer state path and verify that no downstream actor is
        # active before opening the broker subscription for the retained command.
        if writer_state_path.exists():
            writer_state_path.unlink()
        writer_process, _, writer_state_path, writer_log, writer_config = start_writer(
            runtime_directory=arm_runtime / "writer-final",
            thing_id=thing_id,
            bucket=bucket,
            org=org,
            write_token=write_token,
        )
        if not wait_for_writer():
            raise RuntimeError("The final-stage writer did not become ready.")
        open_event_final = set_connection_status(
            devops,
            event_connection_id,
            event_connection_config,
            "open",
        )
        metrics_before_open = read_metrics(devops, mqtt_connection_id)
        open_started = utc_now()
        open_mqtt_final = set_connection_status(
            devops,
            mqtt_connection_id,
            mqtt_connection_config,
            "open",
        )
        retained_thing = wait_for_thing(
            ditto,
            thing_id,
            RETAINED_TEMPERATURE,
            retained_marker,
        )
        malicious_thing_changed = thing_has_values(
            retained_thing,
            RETAINED_TEMPERATURE,
            retained_marker,
        )
        malicious_writer = wait_for_writer_event(
            writer_state_path,
            thing_id,
            RETAINED_TEMPERATURE,
            retained_marker,
            timeout_seconds=8,
        )
        malicious_writer_ok = writer_event_matches(
            malicious_writer,
            thing_id,
            RETAINED_TEMPERATURE,
            retained_marker,
        )
        metrics_after_open = read_metrics(devops, mqtt_connection_id)
        metrics_change = metric_delta(metrics_before_open, metrics_after_open)
        time.sleep(0.5)
        opened_broker_logs = broker_logs(
            docker,
            container_name,
            since_utc=open_started,
        )
        retained_delivery_logs = retained_broker_logs(
            opened_broker_logs,
            since_utc=open_started,
            topic=topic,
        )
        malicious_influx = query_influx(
            read_token=read_token,
            org=org,
            bucket=bucket,
            thing_id=thing_id,
            marker=retained_marker,
        )
        malicious_influx_ok = malicious_influx["status"] == "CONFIRMED"
        evidence["retained"]["downstream_observation"] = {
            "open_started_utc": open_started,
            "event_connection": open_event_final,
            "mqtt_connection": open_mqtt_final,
            "thing_after": retained_thing,
            "writer_event": malicious_writer,
            "influx_readback": malicious_influx,
            "broker_retained_delivery_logs": retained_delivery_logs,
            "mqtt_metrics_before": metrics_before_open,
            "mqtt_metrics_after": metrics_after_open,
            "mqtt_metric_delta": metrics_change,
        }

        post_publisher = MqttConnection(
            "127.0.0.1",
            evidence["deployment"]["host_port"],
            "experiment-health-publisher",
            credentials["experiment-health-publisher"],
            f"cve12546-{arm_name}-post-control-{secrets.token_hex(4)}",
        )
        post_publisher.connect()
        post_publish = post_publisher.publish(
            topic,
            json.dumps(
                ditto_command_payload(
                    thing_id,
                    POST_CONTROL_TEMPERATURE,
                    post_marker,
                ),
                separators=(",", ":"),
            ),
            retained=False,
            qos=1,
        )
        post_publisher.close()
        post_thing = wait_for_thing(
            ditto,
            thing_id,
            POST_CONTROL_TEMPERATURE,
            post_marker,
        )
        post_writer = wait_for_writer_event(
            writer_state_path,
            thing_id,
            POST_CONTROL_TEMPERATURE,
            post_marker,
        )
        post_influx = query_influx(
            read_token=read_token,
            org=org,
            bucket=bucket,
            thing_id=thing_id,
            marker=post_marker,
        )
        post_thing_ok = thing_has_values(
            post_thing,
            POST_CONTROL_TEMPERATURE,
            post_marker,
        )
        post_writer_ok = writer_event_matches(
            post_writer,
            thing_id,
            POST_CONTROL_TEMPERATURE,
            post_marker,
        )
        evidence["post_control"] = {
            "marker": post_marker,
            "temperature": POST_CONTROL_TEMPERATURE,
            "publish": post_publish,
            "thing_after": post_thing,
            "writer_event": post_writer,
            "influx_readback": post_influx,
            "thing_changed": post_thing_ok,
            "writer_event_matches": post_writer_ok,
        }

        evidence["assessment"] = classify_downstream_outcome(
            arm_name=arm_name,
            normal_path_ok=normal_ok,
            revoked_before_retained_delivery=revocation_enforced,
            retained_was_established=retained_established,
            malicious_thing_changed=malicious_thing_changed,
            malicious_writer_event=malicious_writer_ok,
            malicious_influx_row=malicious_influx_ok,
            post_control_thing_changed=post_thing_ok,
            post_control_writer_event=post_writer_ok,
        )
        evidence["assessment"]["influx_readback_status"] = (
            "CONFIRMED_WHERE_PROVIDED"
            if read_token
            else "PENDING_USER_CONFIRMATION"
        )
        evidence["assessment"]["scope"] = (
            "This is one temporary broker-to-Ditto-to-InfluxDB configuration "
            "and observation window. It does not establish clinical impact or "
            "a numerical C/I/A magnitude."
        )
        evidence["assessment"]["status"] = "COMPLETED"
    except Exception as exc:
        evidence["failure"] = f"{type(exc).__name__}: {exc}"
        evidence["assessment"] = {
            "status": "INCONCLUSIVE",
            "outcome": "INCONCLUSIVE",
            "prerequisites_met": False,
            "policy_violation": None,
            "influx_readback_status": (
                "CONFIRMED_WHERE_PROVIDED"
                if read_token
                else "PENDING_USER_CONFIRMATION"
            ),
        }
    finally:
        cleanup = {}
        writer_log_tail = []
        if "writer_log" in locals() and writer_log.exists():
            writer_log_tail = writer_log.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()[-100:]
        try:
            close_event_result = (
                set_connection_status(
                    devops,
                    event_connection_id,
                    event_connection_config,
                    "closed",
                )
                if event_connection_created and event_connection_config
                else {"verified": True}
            )
        except Exception:
            close_event_result = {"verified": False}
        try:
            close_mqtt_result = (
                set_connection_status(
                    devops,
                    mqtt_connection_id,
                    mqtt_connection_config,
                    "closed",
                )
                if mqtt_connection_created and mqtt_connection_config
                else {"verified": True}
            )
        except Exception:
            close_mqtt_result = {"verified": False}
        cleanup["connections_closed_before_cleanup"] = (
            close_event_result.get("verified", False)
            and close_mqtt_result.get("verified", False)
        )
        cleanup["writer_stopped"] = (
            stop_writer(writer_process) if writer_process is not None else True
        )
        cleanup["event_connection_deleted"] = (
            delete_ditto_resource(
                devops,
                f"{BASE_URL}/api/2/connections/{event_connection_id}",
            )
            if event_connection_created
            else True
        )
        cleanup["mqtt_connection_deleted"] = (
            delete_ditto_resource(
                devops,
                f"{BASE_URL}/api/2/connections/{mqtt_connection_id}",
            )
            if mqtt_connection_created
            else True
        )
        cleanup["thing_deleted"] = (
            delete_ditto_resource(
                ditto,
                f"{BASE_URL}/api/2/things/{thing_id}",
            )
            if thing_created
            else True
        )
        cleanup["policy_deleted"] = (
            delete_ditto_resource(
                ditto,
                f"{BASE_URL}/api/2/policies/{policy_id}",
            )
            if policy_created
            else True
        )
        cleanup["temporary_broker_removed"] = (
            cleanup_broker(
                docker,
                container_name,
                f"experiment-2-{suffix}-{arm_name}",
            )
            if broker_created
            else True
        )
        cleanup["runtime_removed"] = clean_private_runtime(arm_runtime)
        cleanup_result = cleanup_assessment(cleanup)
        evidence["cleanup"] = {
            "checks": cleanup,
            "outcome": cleanup_result["outcome"],
            "exit_code": cleanup_result["exit_code"],
            "influx_rows_retained": (
                "Telemetry rows are appended evidence and are not deleted with "
                "the scoped write credential."
            ),
        }
        evidence["finished_utc"] = utc_now()
        evidence["writer_log_tail"] = writer_log_tail
    return evidence


def compare_outcomes(
    vulnerable: dict[str, Any],
    control: dict[str, Any],
) -> dict[str, Any]:
    vulnerable_outcome = vulnerable.get("assessment", {}).get("outcome")
    control_outcome = control.get("assessment", {}).get("outcome")
    if (
        vulnerable_outcome == "POLICY_VIOLATION_OBSERVED"
        and control_outcome == "POLICY_HELD"
    ):
        outcome = "PAIRED_DOWNSTREAM_DIFFERENCE_OBSERVED"
        summary = (
            "The vulnerable retained command changed the isolated Thing and "
            "produced telemetry after verified revocation; the control withheld it."
        )
    elif vulnerable_outcome == "UNEXPECTED_WITHHELD":
        outcome = "VULNERABLE_DOWNSTREAM_EFFECT_NOT_OBSERVED"
        summary = "The vulnerable arm did not update the isolated Thing."
    elif control_outcome == "UNEXPECTED_CONTROL_POLICY_VIOLATION":
        outcome = "CONTROL_POLICY_VIOLATION_OBSERVED"
        summary = "The configured control also updated the Thing after revocation."
    else:
        outcome = "INCONCLUSIVE"
        summary = "At least one arm failed a prerequisite or cleanup check."
    cleanup_ok = all(
        arm.get("cleanup", {}).get("outcome") == "VERIFIED"
        for arm in (vulnerable, control)
    )
    return {
        "outcome": outcome,
        "summary": summary,
        "cleanup_verified": cleanup_ok,
        "assessment_boundary": (
            "The result concerns downstream policy compliance in this lab. "
            "It does not establish clinical harm or C/I/A numerical impact."
        ),
    }


def print_summary(evidence: dict[str, Any], path: Path) -> None:
    print("CVE-2018-12546 DOWNSTREAM RETAINED-MESSAGE EXPERIMENT")
    print(f"RUN_ID={evidence['run_id']}")
    print(f"POLICY={POLICY_TEXT}")
    for arm_name in ("vulnerable", "control"):
        arm = evidence["arms"][arm_name]
        assessment = arm.get("assessment", {})
        retained = arm.get("retained", {}).get(
            "downstream_observation", {}
        )
        print(
            f"{arm_name.upper()}_VERSION="
            f"{arm.get('deployment', {}).get('runtime_version')}"
        )
        print(
            f"{arm_name.upper()}_REVOCATION_ENFORCED="
            f"{arm.get('retained', {}).get('revocation', {}).get('enforced')}"
        )
        print(
            f"{arm_name.upper()}_THING_CHANGED="
            f"{assessment.get('malicious_thing_changed')}"
        )
        print(
            f"{arm_name.upper()}_WRITER_EVENT="
            f"{assessment.get('malicious_writer_event')}"
        )
        print(
            f"{arm_name.upper()}_INFLUX_READBACK="
            f"{retained.get('influx_readback', {}).get('status')}"
        )
        print(
            f"{arm_name.upper()}_OUTCOME="
            f"{assessment.get('outcome')}"
        )
        print(
            f"{arm_name.upper()}_CLEANUP="
            f"{arm.get('cleanup', {}).get('outcome')}"
        )
    comparison = evidence["comparison"]
    print(f"COMPARISON={comparison['outcome']}")
    print(f"CLEANUP_VERIFIED={comparison['cleanup_verified']}")
    print(f"RESULT={evidence['result']}")
    print(f"EVIDENCE={path}")
    for arm_name in ("vulnerable", "control"):
        query = evidence["arms"][arm_name].get("influx_queries", {}).get(
            "retained"
        )
        if query:
            print(f"{arm_name.upper()}_FLUX_QUERY_BEGIN")
            print(query)
            print(f"{arm_name.upper()}_FLUX_QUERY_END")


def flux_query_for(bucket: str, thing_id: str, marker: str) -> str:
    return (
        f'from(bucket: "{bucket}")\n'
        "  |> range(start: -24h)\n"
        '  |> filter(fn: (r) => r._measurement == "ditto_thing_event")\n'
        '  |> filter(fn: (r) => r._field == "temperature")\n'
        f'  |> filter(fn: (r) => r.thing_id == "{thing_id}")\n'
        f'  |> filter(fn: (r) => r.run_marker == "{marker}")\n'
        "  |> last()\n"
        '  |> keep(columns: ["_time", "_value", "thing_id", "run_marker"])'
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bucket", default=DEFAULT_BUCKET)
    parser.add_argument("--org", default=DEFAULT_ORG)
    args = parser.parse_args()

    ditto_password = getpass.getpass(
        "Enter the ordinary Ditto nginx password: "
    )
    write_token = getpass.getpass(
        "Enter the write-only InfluxDB token for the test bucket: "
    )
    read_token = getpass.getpass(
        "Enter the bucket-scoped InfluxDB read token "
        "(press Enter to leave database readback pending): "
    )
    if not ditto_password or not write_token:
        print("The Ditto password and InfluxDB write token are required.")
        return 2

    run_id = (
        "cve-2018-12546-downstream-"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    )
    suffix = secrets.token_hex(5)
    evidence_path = EVIDENCE_ROOT / f"{run_id}.json"
    runtime_root = PRIVATE_ROOT / run_id
    runtime_root.mkdir(parents=True, exist_ok=False)
    if not restrict_local_permissions(runtime_root):
        print("Unable to restrict the private runtime directory.")
        return 2

    docker = DockerClient()
    ditto = requests.Session()
    ditto.trust_env = False
    ditto.auth = HTTPBasicAuth("ditto", ditto_password)
    devops = requests.Session()
    devops.trust_env = False
    devops.auth = HTTPBasicAuth("devops", read_devops_password(docker))

    baseline_before = {}
    for name in (
        "mosquitto-vuln-lab",
        "mosquitto-lab",
        "docker-gateway-1",
        "docker-connectivity-1",
        "influxdb-lab",
    ):
        inspected = docker.json("inspect", name)[0]
        baseline_before[name] = {
            "id": inspected.get("Id"),
            "status": inspected.get("State", {}).get("Status"),
            "started_at": inspected.get("State", {}).get("StartedAt"),
        }

    evidence: dict[str, Any] = {
        "schema_version": "1.0",
        "run_id": run_id,
        "cve_id": "CVE-2018-12546",
        "started_utc": utc_now(),
        "policy": POLICY_TEXT,
        "experiment_1_evidence": (
            "output/evidence_runs/"
            "cve-2018-12546-retained-acl-20261118T195233320714Z.json"
        ),
        "environment": {
            "docker_network": DOCKER_NETWORK,
            "mqtt_protocol": MQTT_VERSION,
            "bucket": args.bucket,
            "org": args.org,
            "baseline_before": baseline_before,
            "existing_connections": current_connection_snapshot(devops),
            "influx_url": INFLUX_URL,
            "writer_url": f"http://{WRITER_HOST}:{WRITER_PORT}",
        },
        "credential_handling": {
            "hidden_prompts": True,
            "credentials_recorded": False,
            "tokens_recorded": False,
            "authorization_headers_recorded": False,
        },
        "arms": {},
    }
    try:
        preflight = downstream_preflight(ditto=ditto, devops=devops)
        evidence["preflight"] = preflight
        if not preflight["verified"]:
            raise RuntimeError("A mandatory Experiment 2 preflight check failed.")
        original_mqtt = request_checked(
            devops,
            "GET",
            f"{BASE_URL}/api/2/connections/{CONNECTION_ID}",
            expected=(200,),
        ).json()
        for arm in (VULNERABLE, CONTROL):
            print(f"Running {arm['arm']} downstream arm...")
            arm_result = run_arm(
                arm=arm,
                docker=docker,
                ditto=ditto,
                devops=devops,
                original_mqtt_connection=original_mqtt,
                version=arm["expected_version"],
                suffix=suffix,
                bucket=args.bucket,
                org=args.org,
                write_token=write_token,
                read_token=read_token,
                runtime_root=runtime_root,
            )
            arm_result["influx_queries"] = {
                "normal": flux_query_for(
                    args.bucket,
                    arm_result["thing_id"],
                    arm_result.get("normal", {}).get("marker", ""),
                ),
                "retained": flux_query_for(
                    args.bucket,
                    arm_result["thing_id"],
                    arm_result.get("retained", {})
                    .get("stored_message_check", {})
                    .get("marker", ""),
                ),
                "post_control": flux_query_for(
                    args.bucket,
                    arm_result["thing_id"],
                    arm_result.get("post_control", {}).get("marker", ""),
                ),
            }
            evidence["arms"][arm["arm"]] = arm_result
    except Exception as exc:
        evidence["fatal_error"] = f"{type(exc).__name__}: {exc}"
    finally:
        ditto.close()
        devops.close()
        baseline_after = {}
        for name in baseline_before:
            inspected = docker.json("inspect", name)[0]
            baseline_after[name] = {
                "id": inspected.get("Id"),
                "status": inspected.get("State", {}).get("Status"),
                "started_at": inspected.get("State", {}).get("StartedAt"),
            }
        evidence["environment"]["baseline_after"] = baseline_after
        evidence["environment"]["baseline_unchanged"] = (
            baseline_before == baseline_after
        )
        evidence["environment"]["runtime_removed"] = clean_private_runtime(
            runtime_root
        )
        evidence["finished_utc"] = utc_now()

    if "vulnerable" in evidence["arms"] and "control" in evidence["arms"]:
        evidence["comparison"] = compare_outcomes(
            evidence["arms"]["vulnerable"],
            evidence["arms"]["control"],
        )
    else:
        evidence["comparison"] = {
            "outcome": "INCONCLUSIVE",
            "summary": "One or both arms did not execute.",
            "cleanup_verified": False,
        }

    readback_complete = all(
        arm.get("assessment", {}).get("influx_readback_status")
        == "CONFIRMED_WHERE_PROVIDED"
        for arm in evidence["arms"].values()
    )
    all_cleanup = (
        evidence["comparison"]["cleanup_verified"]
        and evidence["environment"]["baseline_unchanged"]
        and evidence["environment"]["runtime_removed"]
    )
    if all_cleanup and evidence["comparison"]["outcome"] in (
        "PAIRED_DOWNSTREAM_DIFFERENCE_OBSERVED",
        "VULNERABLE_DOWNSTREAM_EFFECT_NOT_OBSERVED",
        "CONTROL_POLICY_VIOLATION_OBSERVED",
    ):
        evidence["result"] = (
            "COMPLETED"
            if readback_complete
            else "COMPLETED_READBACK_PENDING"
        )
    elif not all_cleanup:
        evidence["result"] = "CLEANUP_FAILED"
    else:
        evidence["result"] = "INCONCLUSIVE"
    EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(
        json.dumps(evidence, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print_summary(evidence, evidence_path)
    return 0 if evidence["result"].startswith("COMPLETED") else 1


if __name__ == "__main__":
    raise SystemExit(main())
