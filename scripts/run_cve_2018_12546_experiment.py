"""Run the isolated CVE-2018-12546 retained-message comparison.

The experiment starts two temporary Mosquitto brokers from exact local image
IDs: vulnerable 1.5.5 and control 2.1.2. Both use equivalent authentication,
ACLs and MQTT listeners. The control explicitly enables check_retain_source.

The only live test is retained delivery after the original publisher's write
permission is revoked. Successful delivery is evidence of the documented
broker behaviour in this configuration; it is not evidence of a downstream
C/I/A consequence.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Callable
import uuid


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_ROOT = ROOT / "output" / "evidence_runs"

CVE_ID = "CVE-2018-12546"
MQTT_VERSION = "3.1.1"
MQTT_PROTOCOL_LEVEL = 4
OBSERVATION_TIMEOUT_SECONDS = 4.0
RELOAD_TIMEOUT_SECONDS = 12

VULNERABLE = {
    "arm": "vulnerable",
    "image_id": (
        "sha256:d8bf12824d7fda2811320320dd18931b2f71b9737db91f88aac8be20a1b9bec5"
    ),
    "image_reference": "efrecon/mosquitto:1.5.5",
    "expected_version": "1.5.5",
    "check_retain_source": None,
}
CONTROL = {
    "arm": "control",
    "image_id": (
        "sha256:6f8d8a947c506f8a2290ec65cd4bd2bc7cb4d43fb5f6271f861cb013e2ef9797"
    ),
    "image_reference": "eclipse-mosquitto:2.1.2-alpine",
    "expected_version": "2.1.2",
    "check_retain_source": True,
}

BASELINE_CONTAINERS = ("mosquitto-vuln-lab", "mosquitto-lab")
EXPERIMENT_LABEL = "io.iomt.experiment"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run_command(
    args: list[str],
    *,
    input_bytes: bytes | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            args,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            args,
            returncode=124,
            stdout=exc.stdout or b"",
            stderr=(
                (exc.stderr or b"")
                + b"\nCommand exceeded its bounded timeout."
            ),
        )


def resolve_docker_executable(explicit: str | None = None) -> str:
    candidates = [
        explicit,
        os.environ.get("DOCKER_EXE"),
        shutil.which("docker"),
        r"C:\Users\aryat\AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(Path(candidate))
    raise FileNotFoundError("The Docker CLI executable could not be found.")


class DockerClient:
    def __init__(self, executable: str | None = None):
        self.executable = resolve_docker_executable(executable)

    def run(
        self,
        *args: str,
        timeout: float = 30,
        allow_failure: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        completed = run_command(
            [self.executable, *args],
            timeout=timeout,
        )
        if completed.returncode != 0 and not allow_failure:
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(
                f"Docker command failed ({completed.returncode}): "
                f"docker {' '.join(args)}: {stderr}"
            )
        return completed

    def output(self, *args: str, timeout: float = 30) -> str:
        return self.run(*args, timeout=timeout).stdout.decode(
            "utf-8", errors="replace"
        )

    def json(self, *args: str, timeout: float = 30) -> Any:
        return json.loads(self.output(*args, timeout=timeout))


def restrict_local_permissions(path: Path) -> bool:
    if os.name != "nt":
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
        return True
    account = os.environ.get("USERNAME") or os.environ.get("USER", "")
    domain = os.environ.get("USERDOMAIN")
    if domain:
        account = f"{domain}\\{account}"
    if not account:
        return False
    inheritance = "(OI)(CI)F" if path.is_dir() else "F"
    completed = run_command(
        [
            "icacls",
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"{account}:{inheritance}",
            "/Q",
        ]
    )
    return completed.returncode == 0


def write_private_text(path: Path, text: str) -> bool:
    path.write_text(text, encoding="utf-8", newline="\n")
    return restrict_local_permissions(path)


def legacy_password_line(username: str, password: str, salt: bytes) -> str:
    """Create the $6$ SHA-512 format understood by Mosquitto 1.5.5."""

    salt64 = base64.b64encode(salt).decode("ascii")
    digest = hashlib.sha512(password.encode("utf-8") + salt).digest()
    digest64 = base64.b64encode(digest).decode("ascii")
    return f"{username}:$6${salt64}${digest64}"


def verify_legacy_password_line(
    line: str,
    username: str,
    password: str,
) -> bool:
    try:
        line_user, encoded = line.split(":", 1)
        parts = encoded.split("$")
        if len(parts) != 4 or parts[0]:
            return False
        _, marker, salt64, digest64 = parts
        if line_user != username or marker != "6":
            return False
        salt = base64.b64decode(salt64, validate=True)
        expected = hashlib.sha512(password.encode("utf-8") + salt).digest()
        return secrets.compare_digest(
            base64.b64encode(expected).decode("ascii"),
            digest64,
        )
    except (ValueError, TypeError):
        return False


def redact_process_output(completed: subprocess.CompletedProcess[bytes]) -> str:
    output = (completed.stdout + completed.stderr).decode(
        "utf-8", errors="replace"
    )
    return output.replace("\r\n", "\n").strip()


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


def read_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = sock.recv(length - len(chunks))
        if not chunk:
            raise RuntimeError("MQTT connection closed unexpectedly.")
        chunks.extend(chunk)
    return bytes(chunks)


def read_mqtt_packet(sock: socket.socket) -> tuple[int, bytes]:
    first = read_exact(sock, 1)[0]
    multiplier = 1
    remaining = 0
    while True:
        byte = read_exact(sock, 1)[0]
        remaining += (byte & 0x7F) * multiplier
        if not byte & 0x80:
            break
        multiplier *= 128
        if multiplier > 128**3:
            raise RuntimeError("Malformed MQTT remaining length.")
    return first, read_exact(sock, remaining)


def decode_mqtt_publish(header: int, body: bytes) -> dict[str, Any]:
    if len(body) < 2:
        raise RuntimeError("Malformed MQTT PUBLISH.")
    topic_length = struct.unpack("!H", body[:2])[0]
    topic_end = 2 + topic_length
    if len(body) < topic_end:
        raise RuntimeError("Malformed MQTT PUBLISH topic.")
    topic = body[2:topic_end].decode("utf-8")
    qos = (header >> 1) & 0x03
    offset = topic_end
    packet_id = None
    if qos:
        if len(body) < offset + 2:
            raise RuntimeError("Malformed MQTT PUBLISH packet identifier.")
        packet_id = struct.unpack("!H", body[offset : offset + 2])[0]
        offset += 2
    return {
        "topic": topic,
        "payload": body[offset:].decode("utf-8", errors="replace"),
        "qos": qos,
        "retained": bool(header & 0x01),
        "packet_id": packet_id,
    }


class MqttConnection:
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        client_id: str,
        timeout: float = OBSERVATION_TIMEOUT_SECONDS,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client_id = client_id
        self.timeout = timeout
        self.socket: socket.socket | None = None
        self.connect_result: dict[str, Any] = {}

    def connect(self) -> dict[str, Any]:
        sock = socket.create_connection((self.host, self.port), timeout=5)
        sock.settimeout(self.timeout)
        self.socket = sock
        variable_header = (
            encode_string("MQTT")
            + bytes([MQTT_PROTOCOL_LEVEL, 0xC2])
            + struct.pack("!H", 30)
        )
        payload = (
            encode_string(self.client_id)
            + encode_string(self.username)
            + encode_string(self.password)
        )
        sock.sendall(mqtt_packet(1, 0, variable_header + payload))
        packet_type, body = read_mqtt_packet(sock)
        if packet_type >> 4 != 2 or len(body) != 2:
            raise RuntimeError("Malformed MQTT CONNACK.")
        result = {
            "accepted": body[1] == 0,
            "return_code": body[1],
            "session_present": bool(body[0] & 0x01),
            "client_id": self.client_id,
            "captured_utc": utc_now(),
        }
        self.connect_result = result
        if not result["accepted"]:
            raise RuntimeError(
                f"MQTT authentication failed with code {body[1]}."
            )
        return result

    def subscribe(self, topic: str, qos: int = 1) -> dict[str, Any]:
        if self.socket is None:
            raise RuntimeError("MQTT connection is not open.")
        packet_id = int(uuid.uuid4().int % 65535) + 1
        payload = struct.pack("!H", packet_id) + encode_string(topic) + bytes([qos])
        self.socket.sendall(mqtt_packet(8, 2, payload))
        while True:
            header, body = read_mqtt_packet(self.socket)
            if header >> 4 == 9:
                if len(body) < 3:
                    raise RuntimeError("Malformed MQTT SUBACK.")
                if struct.unpack("!H", body[:2])[0] != packet_id:
                    raise RuntimeError("MQTT SUBACK identifier mismatch.")
                return {
                    "subscribed_utc": utc_now(),
                    "topic": topic,
                    "granted_qos": body[2],
                    "return_code": body[2],
                }

    def publish(self, topic: str, payload: str, *, retained: bool, qos: int = 1):
        if self.socket is None:
            raise RuntimeError("MQTT connection is not open.")
        packet_id = int(uuid.uuid4().int % 65535) + 1
        body = encode_string(topic)
        if qos:
            body += struct.pack("!H", packet_id)
        body += payload.encode("utf-8")
        started = utc_now()
        self.socket.sendall(mqtt_packet(3, (qos << 1) | int(retained), body))
        puback = False
        error = None
        if qos:
            try:
                while True:
                    header, response = read_mqtt_packet(self.socket)
                    if header >> 4 == 4:
                        if len(response) != 2:
                            raise RuntimeError("Malformed MQTT PUBACK.")
                        if struct.unpack("!H", response)[0] != packet_id:
                            raise RuntimeError("MQTT PUBACK identifier mismatch.")
                        puback = True
                        break
            except (OSError, RuntimeError) as exc:
                error = f"{type(exc).__name__}: {exc}"
        return {
            "topic": topic,
            "payload_marker": payload,
            "qos": qos,
            "retained": retained,
            "packet_id": packet_id,
            "publication_attempted_utc": started,
            "puback_received": puback,
            "puback_received_utc": utc_now() if puback else None,
            "error": error,
        }

    def read_publish(self, timeout: float | None = None) -> dict[str, Any] | None:
        if self.socket is None:
            raise RuntimeError("MQTT connection is not open.")
        self.socket.settimeout(
            self.timeout if timeout is None else timeout
        )
        try:
            while True:
                header, body = read_mqtt_packet(self.socket)
                if header >> 4 != 3:
                    continue
                message = decode_mqtt_publish(header, body)
                message["received_utc"] = utc_now()
                message["subscriber_client_id"] = self.client_id
                if message["qos"] == 1 and message["packet_id"] is not None:
                    self.socket.sendall(
                        mqtt_packet(
                            4,
                            0,
                            struct.pack("!H", message["packet_id"]),
                        )
                    )
                return message
        except socket.timeout:
            return None

    def collect_for(
        self,
        seconds: float,
        *,
        after_marker: str | None = None,
    ) -> list[dict[str, Any]]:
        deadline = time.monotonic() + seconds
        messages: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            remaining = max(0.1, deadline - time.monotonic())
            message = self.read_publish(timeout=remaining)
            if message is None:
                break
            messages.append(message)
            if after_marker is not None and message["payload"] == after_marker:
                break
        return messages

    def close(self) -> None:
        if self.socket is None:
            return
        try:
            self.socket.sendall(b"\xE0\x00")
        except OSError:
            pass
        try:
            self.socket.close()
        finally:
            self.socket = None


def broker_configuration(check_retain_source: bool | None) -> str:
    lines = [
        "listener 1883 0.0.0.0",
        "protocol mqtt",
        "allow_anonymous false",
        "password_file /mosquitto/config/passwd",
        "acl_file /mosquitto/config/aclfile",
        "persistence false",
        "log_dest stdout",
        "log_type all",
    ]
    if check_retain_source is not None:
        lines.append(
            "check_retain_source "
            + ("true" if check_retain_source else "false")
        )
    return "\n".join(lines) + "\n"


def initial_acl(topic: str) -> str:
    return (
        "user experiment-publisher\n"
        f"topic write {topic}\n\n"
        "user experiment-subscriber\n"
        f"topic read {topic}\n\n"
        "user experiment-health-publisher\n"
        f"topic write {topic}\n"
    )


def revoked_acl(topic: str) -> str:
    # Removing the original publisher's block leaves it without topic access.
    return (
        "user experiment-subscriber\n"
        f"topic read {topic}\n\n"
        "user experiment-health-publisher\n"
        f"topic write {topic}\n"
    )


def atomic_write_text(path: Path, text: str) -> None:
    staged = path.with_name(path.name + ".staged")
    staged.write_text(text, encoding="utf-8", newline="\n")
    os.replace(staged, path)


def wait_for_tcp(host: str, port: int, timeout_seconds: int = 20) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def host_port(docker: DockerClient, container: str, container_port: int) -> int:
    inspected = docker.json("inspect", container)[0]
    bindings = (
        inspected.get("NetworkSettings", {})
        .get("Ports", {})
        .get(f"{container_port}/tcp")
        or []
    )
    if not bindings:
        raise RuntimeError(f"No host port is mapped for {container_port}/tcp.")
    return int(bindings[0]["HostPort"])


def broker_process_lines(docker: DockerClient, container: str) -> list[str]:
    completed = docker.run(
        "exec",
        container,
        "ps",
        "-eo",
        "pid,comm",
        allow_failure=True,
    )
    return completed.stdout.decode("utf-8", errors="replace").splitlines()


def find_broker_pid(lines: list[str]) -> int:
    for line in lines:
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "mosquitto":
            return int(fields[0])
    raise RuntimeError("The Mosquitto broker process was not found.")


def reload_broker(
    docker: DockerClient,
    container: str,
    *,
    wait_for_reload: Callable[[str], bool],
) -> dict[str, Any]:
    before = utc_now()
    pid = find_broker_pid(broker_process_lines(docker, container))
    completed = docker.run("exec", container, "kill", "-HUP", str(pid))
    deadline = time.monotonic() + RELOAD_TIMEOUT_SECONDS
    reload_seen = False
    while time.monotonic() < deadline:
        if wait_for_reload(before):
            reload_seen = True
            break
        time.sleep(0.25)
    return {
        "signal": "SIGHUP",
        "broker_pid": pid,
        "sent_utc": before,
        "command_succeeded": completed.returncode == 0,
        "reload_log_observed": reload_seen,
    }


def broker_logs(
    docker: DockerClient,
    container: str,
    *,
    since_utc: str,
) -> list[str]:
    output = docker.output(
        "logs",
        "--timestamps",
        "--since",
        since_utc,
        container,
        timeout=30,
    )
    return output.replace("\r\n", "\n").splitlines()


def line_time(line: str) -> datetime | None:
    match = re.match(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)",
        line,
    )
    if not match:
        return None
    return datetime.fromisoformat(match.group(1).replace("Z", "+00:00"))


def find_reload_log(lines: list[str], since_utc: str) -> bool:
    since = datetime.fromisoformat(since_utc.replace("Z", "+00:00"))
    return any(
        (timestamp := line_time(line)) is not None
        and timestamp >= since
        and "Reloading config" in line
        for line in lines
    )


def find_denial_log(
    lines: list[str],
    since_utc: str,
    topic: str,
    client_id: str,
) -> list[str]:
    since = datetime.fromisoformat(since_utc.replace("Z", "+00:00"))
    matches = []
    for line in lines:
        timestamp = line_time(line)
        if timestamp is None or timestamp < since:
            continue
        lowered = line.lower()
        if (
            topic in line
            and client_id in line
            and "denied" in lowered
            and "publish" in lowered
        ):
            matches.append(line)
    return matches


def classify_arm(
    arm: dict[str, Any],
    *,
    runtime_version: str,
    auth_rejected_bad_password: bool,
    initial_marker_delivered: bool,
    revocation_enforced: bool,
    stale_marker_delivered: bool,
    replacement_marker_delivered: bool,
) -> dict[str, Any]:
    prerequisites_met = (
        runtime_version == arm["expected_version"]
        and auth_rejected_bad_password
        and initial_marker_delivered
        and revocation_enforced
        and replacement_marker_delivered
    )
    if not prerequisites_met:
        outcome = "INCONCLUSIVE"
        interpretation = (
            "One or more mandatory prerequisites or control checks failed."
        )
    elif arm["arm"] == "vulnerable":
        if stale_marker_delivered:
            outcome = "CVE_BEHAVIOUR_OBSERVED"
            interpretation = (
                "A fresh authorized subscriber received the retained marker "
                "after enforced publisher revocation."
            )
        else:
            outcome = "UNEXPECTED_WITHHELD"
            interpretation = (
                "The vulnerable configuration did not reproduce the "
                "documented retained-delivery behaviour."
            )
    else:
        if stale_marker_delivered:
            outcome = "UNEXPECTED_DELIVERY"
            interpretation = (
                "The control delivered the original retained marker despite "
                "check_retain_source=true and enforced publisher revocation."
            )
        else:
            outcome = "CONTROL_BEHAVIOUR_OBSERVED"
            interpretation = (
                "The control withheld the original retained marker after "
                "enforced publisher revocation while subscriber access remained available."
            )
    return {
        "prerequisites_met": prerequisites_met,
        "outcome": outcome,
        "interpretation": interpretation,
        "scope": (
            "This temporary broker, topic, source identity, ACL transition, "
            "MQTT 3.1.1 client and observation window only."
        ),
    }


def compare_arms(
    vulnerable_result: dict[str, Any],
    control_result: dict[str, Any],
) -> dict[str, Any]:
    v_outcome = vulnerable_result.get("assessment", {}).get("outcome")
    c_outcome = control_result.get("assessment", {}).get("outcome")
    if (
        v_outcome == "CVE_BEHAVIOUR_OBSERVED"
        and c_outcome == "CONTROL_BEHAVIOUR_OBSERVED"
    ):
        outcome = "PAIRED_DIFFERENCE_OBSERVED"
        supports_reproduction = True
        summary = (
            "The vulnerable arm delivered the old retained marker after "
            "revocation; the configured control withdrew it."
        )
    elif (
        v_outcome == "CVE_BEHAVIOUR_OBSERVED"
        and c_outcome == "UNEXPECTED_DELIVERY"
    ):
        outcome = "NO_CONFIGURED_CONTROL_EFFECT_OBSERVED"
        supports_reproduction = True
        summary = (
            "The vulnerable arm reproduced the behaviour, but the control "
            "also delivered it in this configuration."
        )
    elif v_outcome == "UNEXPECTED_WITHHELD":
        outcome = "VULNERABLE_BEHAVIOUR_NOT_REPRODUCED"
        supports_reproduction = False
        summary = (
            "The vulnerable arm did not show the documented retained delivery."
        )
    else:
        outcome = "INCONCLUSIVE"
        supports_reproduction = False
        summary = "The paired result is incomplete or prerequisite checks failed."
    return {
        "outcome": outcome,
        "supports_cve_broker_behaviour_reproduction": supports_reproduction,
        "summary": summary,
        "does_not_establish": [
            "target confidentiality, integrity or availability magnitude",
            "downstream Ditto or InfluxDB impact",
            "attack feasibility outside the tested ACL transition",
            "that Mosquitto 2.1.2 is generally secure",
        ],
    }


def cleanup_assessment(checks: dict[str, Any]) -> dict[str, Any]:
    required = {key: value for key, value in checks.items() if value is not None}
    verified = bool(required) and all(value is True for value in required.values())
    return {
        "outcome": "VERIFIED" if verified else "FAILED",
        "exit_code": 0 if verified else 1,
        "checks": required,
    }


def write_evidence(path: Path, evidence: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(evidence, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temporary, path)


def capture_existing_baseline_states(docker: DockerClient) -> dict[str, Any]:
    states: dict[str, Any] = {}
    for name in BASELINE_CONTAINERS:
        completed = docker.run(
            "inspect",
            name,
            "--format",
            "{{json .State}}",
            allow_failure=True,
        )
        states[name] = (
            json.loads(completed.stdout.decode("utf-8"))
            if completed.returncode == 0
            else {"unavailable": True}
        )
    return states


def image_metadata(docker: DockerClient, image_id: str) -> dict[str, Any]:
    inspected = docker.json("image", "inspect", image_id)[0]
    return {
        "image_id": inspected.get("Id"),
        "repo_tags": inspected.get("RepoTags") or [],
        "created": inspected.get("Created"),
        "architecture": inspected.get("Architecture"),
        "os": inspected.get("Os"),
        "labels": inspected.get("Config", {}).get("Labels") or {},
    }


def start_broker(
    docker: DockerClient,
    *,
    arm: dict[str, Any],
    container_name: str,
    network_name: str,
    config_directory: Path,
    experiment_id: str,
) -> dict[str, Any]:
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
        network_name,
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
    ready = wait_for_tcp("127.0.0.1", port)
    inspected = docker.json("inspect", container_name)[0]
    identity = docker.output("exec", container_name, "id")
    runtime = docker.run(
        "exec",
        container_name,
        "/usr/sbin/mosquitto",
        "-h",
        allow_failure=True,
    )
    version_match = re.search(
        r"mosquitto version ([0-9][^\s]*)",
        redact_process_output(runtime),
    )
    return {
        "container_name": container_name,
        "container_id": inspected.get("Id"),
        "image_id": inspected.get("Image"),
        "image_reference": arm["image_reference"],
        "network": network_name,
        "host": "127.0.0.1",
        "host_port": port,
        "started_utc": inspected.get("State", {}).get("StartedAt"),
        "ready": ready,
        "runtime_version": version_match.group(1) if version_match else None,
        "runtime_output": redact_process_output(runtime),
        "process_identity_output": identity.strip(),
        "configuration": broker_configuration(arm["check_retain_source"]),
    }


def run_arm(
    docker: DockerClient,
    *,
    arm: dict[str, Any],
    container_name: str,
    network_name: str,
    runtime_directory: Path,
    experiment_id: str,
    credentials: dict[str, str],
    topic: str,
) -> dict[str, Any]:
    arm_started = utc_now()
    config_directory = runtime_directory / arm["arm"]
    config_directory.mkdir(parents=True, exist_ok=False)
    if not restrict_local_permissions(config_directory):
        raise RuntimeError("Unable to restrict the temporary config directory.")
    if not write_private_text(
        config_directory / "passwd",
        "\n".join(
            legacy_password_line(user, password, os.urandom(12))
            for user, password in credentials.items()
        )
        + "\n",
    ):
        raise RuntimeError("Unable to restrict the temporary password file.")
    if not write_private_text(
        config_directory / "mosquitto.conf",
        broker_configuration(arm["check_retain_source"]),
    ):
        raise RuntimeError("Unable to restrict the temporary broker config.")
    if not write_private_text(
        config_directory / "aclfile",
        initial_acl(topic),
    ):
        raise RuntimeError("Unable to restrict the temporary ACL file.")

    result: dict[str, Any] = {
        "arm": arm["arm"],
        "arm_started_utc": arm_started,
        "expected": {
            "vulnerable": (
                "Stale retained marker delivered after enforced publisher revocation."
            ),
            "control": (
                "Original retained marker withheld with check_retain_source=true, "
                "while the subscriber permission remains valid."
            ),
        }[arm["arm"]],
        "authentication": {},
        "initial_permission": {},
        "revocation": {},
        "post_revocation_observation": {},
        "subscriber_control": {},
        "delivery_counts": {},
    }
    try:
        result["deployment"] = start_broker(
            docker,
            arm=arm,
            container_name=container_name,
            network_name=network_name,
            config_directory=config_directory,
            experiment_id=experiment_id,
        )
        if not result["deployment"]["ready"]:
            raise RuntimeError("The temporary broker did not open its MQTT port.")

        marker = (
            f"IOMT-CVE-2018-12546-{arm['arm'].upper()}-"
            f"{experiment_id[-12:]}-{secrets.token_hex(4)}"
        )
        probe_marker = marker + "-REVOKED-PROBE"
        replacement_marker = marker + "-HEALTHY-REPLACEMENT"
        result["markers"] = {
            "initial": marker,
            "revoked_probe": probe_marker,
            "replacement": replacement_marker,
        }

        bad_client = MqttConnection(
            "127.0.0.1",
            result["deployment"]["host_port"],
            "experiment-publisher",
            "not-the-generated-credential",
            f"cve12546-{arm['arm']}-bad-auth-{secrets.token_hex(4)}",
        )
        try:
            bad_client.connect()
            bad_auth_rejected = False
            bad_code = bad_client.connect_result.get("return_code")
        except RuntimeError as exc:
            bad_auth_rejected = "authentication failed with code" in str(exc)
            bad_code = (
                bad_client.connect_result.get("return_code")
                if bad_client.connect_result
                else None
            )
        finally:
            bad_client.close()
        result["authentication"]["wrong_password_rejected"] = bad_auth_rejected
        result["authentication"]["wrong_password_return_code"] = bad_code

        publisher_id = f"cve12546-{arm['arm']}-publisher-{secrets.token_hex(4)}"
        publisher = MqttConnection(
            "127.0.0.1",
            result["deployment"]["host_port"],
            "experiment-publisher",
            credentials["experiment-publisher"],
            publisher_id,
        )
        publisher_connect = publisher.connect()
        initial_publish = publisher.publish(
            topic,
            marker,
            retained=True,
            qos=1,
        )
        publisher.close()

        initial_subscriber_id = (
            f"cve12546-{arm['arm']}-initial-sub-{secrets.token_hex(4)}"
        )
        initial_subscriber = MqttConnection(
            "127.0.0.1",
            result["deployment"]["host_port"],
            "experiment-subscriber",
            credentials["experiment-subscriber"],
            initial_subscriber_id,
        )
        initial_subscriber.connect()
        initial_subscribe = initial_subscriber.subscribe(topic)
        initial_messages = initial_subscriber.collect_for(
            OBSERVATION_TIMEOUT_SECONDS,
            after_marker=marker,
        )
        initial_subscriber.close()
        initial_delivered = any(
            message["payload"] == marker for message in initial_messages
        )
        result["authentication"]["publisher_accepted"] = publisher_connect["accepted"]
        result["authentication"]["subscriber_accepted"] = (
            initial_subscriber.connect_result["accepted"]
        )
        result["initial_permission"] = {
            "publisher_client_id": publisher_id,
            "publisher_connect": publisher_connect,
            "retained_publication": initial_publish,
            "subscriber_client_id": initial_subscriber_id,
            "subscribe": initial_subscribe,
            "raw_subscriber_messages": initial_messages,
            "retained_marker_delivered": initial_delivered,
        }
        result["delivery_counts"]["initial"] = sum(
            message["payload"] == marker for message in initial_messages
        )

        change_started = utc_now()
        atomic_write_text(config_directory / "aclfile", revoked_acl(topic))
        result["revocation"]["acl_snapshot"] = {
            "before": initial_acl(topic),
            "after": revoked_acl(topic),
            "change_requested_utc": change_started,
        }
        reload_result = reload_broker(
            docker,
            container_name,
            wait_for_reload=lambda since: any(
                find_reload_log(
                    broker_logs(docker, container_name, since_utc=since),
                    since,
                )
                for _ in [0]
            ),
        )
        result["revocation"]["reload"] = reload_result

        observer_id = (
            f"cve12546-{arm['arm']}-revocation-observer-"
            f"{secrets.token_hex(4)}"
        )
        observer = MqttConnection(
            "127.0.0.1",
            result["deployment"]["host_port"],
            "experiment-subscriber",
            credentials["experiment-subscriber"],
            observer_id,
        )
        observer.connect()
        observer.subscribe(topic)
        retained_before_probe = observer.collect_for(
            OBSERVATION_TIMEOUT_SECONDS,
            after_marker=marker,
        )

        revoked_publisher_id = (
            f"cve12546-{arm['arm']}-revoked-publisher-"
            f"{secrets.token_hex(4)}"
        )
        revoked_publisher = MqttConnection(
            "127.0.0.1",
            result["deployment"]["host_port"],
            "experiment-publisher",
            credentials["experiment-publisher"],
            revoked_publisher_id,
        )
        revoked_publisher.connect()
        revoked_publish = revoked_publisher.publish(
            topic,
            probe_marker,
            retained=True,
            qos=1,
        )
        revoked_publisher.close()
        time.sleep(0.5)
        probe_messages = observer.collect_for(OBSERVATION_TIMEOUT_SECONDS)
        observer.close()
        probe_delivered = any(
            message["payload"] == probe_marker for message in probe_messages
        )
        revocation_log_start = (
            revoked_publish["publication_attempted_utc"]
        )
        time.sleep(0.5)
        revocation_logs = broker_logs(
            docker,
            container_name,
            since_utc=revocation_log_start,
        )
        denial_lines = find_denial_log(
            revocation_logs,
            revocation_log_start,
            topic,
            revoked_publisher_id,
        )
        result["revocation"]["enforcement_probe"] = {
            "publisher_client_id": revoked_publisher_id,
            "publisher_connect": revoked_publisher.connect_result,
            "publication": revoked_publish,
            "observer_client_id": observer_id,
            "retained_seen_before_probe": retained_before_probe,
            "probe_messages_after_attempt": probe_messages,
            "probe_marker_delivered": probe_delivered,
            "broker_denial_log_lines": denial_lines,
            "public_acceptance_not_inferred_from_puback": True,
        }
        revocation_enforced = (
            bool(denial_lines)
            and not probe_delivered
        )
        result["revocation"]["enforced"] = revocation_enforced

        stale_subscriber_id = (
            f"cve12546-{arm['arm']}-post-revocation-sub-"
            f"{secrets.token_hex(4)}"
        )
        stale_subscriber = MqttConnection(
            "127.0.0.1",
            result["deployment"]["host_port"],
            "experiment-subscriber",
            credentials["experiment-subscriber"],
            stale_subscriber_id,
        )
        stale_subscriber.connect()
        stale_subscribe = stale_subscriber.subscribe(topic)
        stale_messages = stale_subscriber.collect_for(
            OBSERVATION_TIMEOUT_SECONDS,
            after_marker=marker,
        )
        stale_subscriber.close()
        stale_delivered = any(
            message["payload"] == marker for message in stale_messages
        )
        result["post_revocation_observation"] = {
            "subscriber_client_id": stale_subscriber_id,
            "subscribe": stale_subscribe,
            "raw_subscriber_messages": stale_messages,
            "original_retained_marker_delivered": stale_delivered,
            "observation_timeout_seconds": OBSERVATION_TIMEOUT_SECONDS,
        }
        result["delivery_counts"]["stale_original_marker"] = sum(
            message["payload"] == marker for message in stale_messages
        )

        health_id = (
            f"cve12546-{arm['arm']}-health-publisher-"
            f"{secrets.token_hex(4)}"
        )
        health_publisher = MqttConnection(
            "127.0.0.1",
            result["deployment"]["host_port"],
            "experiment-health-publisher",
            credentials["experiment-health-publisher"],
            health_id,
        )
        health_publisher.connect()
        health_publish = health_publisher.publish(
            topic,
            replacement_marker,
            retained=True,
            qos=1,
        )
        health_publisher.close()

        access_subscriber_id = (
            f"cve12546-{arm['arm']}-access-control-sub-"
            f"{secrets.token_hex(4)}"
        )
        access_subscriber = MqttConnection(
            "127.0.0.1",
            result["deployment"]["host_port"],
            "experiment-subscriber",
            credentials["experiment-subscriber"],
            access_subscriber_id,
        )
        access_subscriber.connect()
        access_subscribes = access_subscriber.subscribe(topic)
        access_messages = access_subscriber.collect_for(
            OBSERVATION_TIMEOUT_SECONDS,
            after_marker=replacement_marker,
        )
        access_subscriber.close()
        replacement_delivered = any(
            message["payload"] == replacement_marker
            for message in access_messages
        )
        result["subscriber_control"] = {
            "publisher_client_id": health_id,
            "publisher_connect": health_publisher.connect_result,
            "publication": health_publish,
            "subscriber_client_id": access_subscriber_id,
            "subscribe": access_subscribes,
            "raw_subscriber_messages": access_messages,
            "replacement_marker_delivered": replacement_delivered,
        }
        result["delivery_counts"]["replacement_marker"] = sum(
            message["payload"] == replacement_marker for message in access_messages
        )

        result["final_configuration"] = {
            "broker_configuration": broker_configuration(
                arm["check_retain_source"]
            ),
            "acl": revoked_acl(topic),
            "password_file": "[REDACTED: generated credentials; not persisted]",
        }
        result["broker_log_lines"] = broker_logs(
            docker,
            container_name,
            since_utc=arm_started,
        )
        result["assessment"] = classify_arm(
            arm,
            runtime_version=result["deployment"]["runtime_version"] or "",
            auth_rejected_bad_password=bad_auth_rejected,
            initial_marker_delivered=initial_delivered,
            revocation_enforced=revocation_enforced,
            stale_marker_delivered=stale_delivered,
            replacement_marker_delivered=replacement_delivered,
        )
        return result
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["assessment"] = {
            "prerequisites_met": False,
            "outcome": "INCONCLUSIVE",
            "interpretation": "The arm failed before all controls completed.",
        }
        try:
            result["broker_log_lines"] = broker_logs(
                docker,
                container_name,
                since_utc=arm_started,
            )
        except Exception:
            result["broker_log_lines"] = []
        return result


def cleanup_temporary_resources(
    docker: DockerClient,
    *,
    container_names: list[str],
    network_name: str,
    experiment_id: str,
    runtime_directory: Path,
) -> dict[str, Any]:
    checks: dict[str, Any] = {}
    for name in container_names:
        inspected = docker.run(
            "inspect",
            name,
            "--format",
            f'{{{{ index .Config.Labels "{EXPERIMENT_LABEL}" }}}}',
            allow_failure=True,
        )
        if inspected.returncode == 0:
            label = inspected.stdout.decode("utf-8", errors="replace").strip()
            if label != experiment_id:
                checks[f"{name}_owned"] = False
                continue
        docker.run("rm", "--force", name, allow_failure=True)
        remaining = docker.run(
            "container",
            "inspect",
            name,
            allow_failure=True,
        )
        checks[f"{name}_removed"] = remaining.returncode != 0
    network = docker.run(
        "network",
        "inspect",
        network_name,
        "--format",
        f'{{{{ index .Labels "{EXPERIMENT_LABEL}" }}}}',
        allow_failure=True,
    )
    if network.returncode == 0:
        label = network.stdout.decode("utf-8", errors="replace").strip()
        checks["network_owned"] = label == experiment_id
        if label == experiment_id:
            docker.run("network", "rm", network_name, allow_failure=True)
    else:
        checks["network_owned"] = True
    remaining_network = docker.run(
        "network",
        "inspect",
        network_name,
        allow_failure=True,
    )
    checks["network_removed"] = remaining_network.returncode != 0

    resolved_runtime = runtime_directory.resolve()
    expected_parent = (ROOT / "output" / "evidence_runs").resolve()
    if (
        resolved_runtime.parent != expected_parent
        or not resolved_runtime.name.startswith(".cve")
    ):
        checks["runtime_directory_scope"] = False
    else:
        if resolved_runtime.exists():
            shutil.rmtree(resolved_runtime)
        checks["runtime_directory_removed"] = not resolved_runtime.exists()
    return checks


def print_terminal_summary(evidence: dict[str, Any], evidence_path: Path) -> None:
    vulnerable = evidence["arms"]["vulnerable"]
    control = evidence["arms"]["control"]
    comparison = evidence["comparison"]
    cleanup = evidence["cleanup"]
    print("CVE-2018-12546 CONTROLLED RETAINED-MESSAGE EXPERIMENT")
    print(f"CVE={CVE_ID}")
    print(f"RUN_ID={evidence['run_id']}")
    for label, arm in (("VULNERABLE", vulnerable), ("CONTROL", control)):
        dep = arm.get("deployment", {})
        outcome = arm.get("assessment", {})
        print(
            f"{label}_VERSION={dep.get('runtime_version', 'UNKNOWN')} "
            f"IMAGE={dep.get('image_reference', 'UNKNOWN')}"
        )
        print(
            f"{label}_INITIAL_DELIVERY="
            f"{arm.get('initial_permission', {}).get('retained_marker_delivered', False)}"
        )
        print(
            f"{label}_REVOCATION_ENFORCED="
            f"{arm.get('revocation', {}).get('enforced', False)}"
        )
        print(
            f"{label}_STALE_DELIVERY="
            f"{arm.get('post_revocation_observation', {}).get('original_retained_marker_delivered', False)}"
        )
        print(
            f"{label}_SUBSCRIBER_ACCESS_PRESERVED="
            f"{arm.get('subscriber_control', {}).get('replacement_marker_delivered', False)}"
        )
        print(f"{label}_OUTCOME={outcome.get('outcome', 'INCONCLUSIVE')}")
    print(f"COMPARISON={comparison['outcome']}")
    print(
        "SUPPORTS_CVE_BROKER_BEHAVIOUR_REPRODUCTION="
        f"{str(comparison['supports_cve_broker_behaviour_reproduction']).lower()}"
    )
    print(f"CLEANUP={cleanup['outcome']}")
    print(f"RESULT={evidence['result']}")
    print(f"EVIDENCE={evidence_path}")


def main() -> int:
    run_id = (
        "cve-2018-12546-retained-acl-"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    )
    experiment_id = "cve12546-" + secrets.token_hex(6)
    runtime_directory = EVIDENCE_ROOT / f".cve-{experiment_id}"
    evidence_path = EVIDENCE_ROOT / f"{run_id}.json"
    network_name = f"iomt-cve12546-{secrets.token_hex(4)}"
    vulnerable_name = f"iomt-cve12546-vuln-{secrets.token_hex(4)}"
    control_name = f"iomt-cve12546-control-{secrets.token_hex(4)}"
    topic = f"iomt/experiments/cve-2018-12546/{experiment_id}"
    credentials = {
        "experiment-publisher": secrets.token_urlsafe(24),
        "experiment-subscriber": secrets.token_urlsafe(24),
        "experiment-health-publisher": secrets.token_urlsafe(24),
    }
    run_started = utc_now()
    docker = DockerClient()
    baseline_before = capture_existing_baseline_states(docker)
    EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
    runtime_directory.mkdir(parents=True, exist_ok=False)
    if not restrict_local_permissions(runtime_directory):
        print("Unable to restrict the temporary runtime directory.")
        return 2

    evidence: dict[str, Any] = {
        "schema_version": "1.0",
        "run_id": run_id,
        "experiment_id": experiment_id,
        "cve_id": CVE_ID,
        "run_started_utc": run_started,
        "environment": {
            "docker_executable": docker.executable,
            "docker_version": None,
            "mqtt_protocol": MQTT_VERSION,
            "topic": topic,
            "isolated_network": network_name,
            "baseline_deployment_states_before": baseline_before,
            "baseline_deployments_used": False,
            "ditto_or_influx_connected": False,
        },
        "advisory_and_expected_semantics": {
            "authoritative_sources": [
                "https://github.com/eclipse-mosquitto/mosquitto/blob/v1.5.6/ChangeLog.txt",
                "https://github.com/eclipse-mosquitto/mosquitto/blob/v1.5.6/mosquitto.conf",
                "https://github.com/eclipse-mosquitto/mosquitto/blob/v1.5.6/man/mosquitto.conf.5.xml",
                "https://github.com/eclipse-mosquitto/mosquitto/blob/v1.5.6/src/subs.c",
            ],
            "affected_versions": "1.0 through 1.5.5 inclusive",
            "retained_source_check": (
                "The subscriber's current READ permission is checked first. "
                "With check_retain_source enabled, a stored publisher identity "
                "is also checked for WRITE permission on the retained topic."
            ),
            "denial_behaviour": (
                "A denied source WRITE check skips retained delivery without "
                "stopping an otherwise authorized subscription."
            ),
            "control_default": (
                "Mosquitto 2.1.2 defaults check_retain_source to true; the "
                "experiment sets it explicitly for reproducibility."
            ),
            "expected": {
                "vulnerable_1_5_5": (
                    "No source check exists; old retained marker is expected "
                    "after the publisher loses WRITE access."
                ),
                "control_2_1_2": (
                    "With check_retain_source=true, the old retained marker is "
                    "expected to be withheld if revocation is enforced."
                ),
            },
        },
        "images": {},
        "credentials": {
            "method": "ephemeral locally generated; never persisted in evidence",
            "password_file_persisted": False,
        },
        "arms": {},
    }
    try:
        evidence["environment"]["docker_version"] = json.loads(
            docker.output("version", "--format", "{{json .}}")
        )
        evidence["images"] = {
            "vulnerable": image_metadata(docker, VULNERABLE["image_id"]),
            "control": image_metadata(docker, CONTROL["image_id"]),
        }
        for arm in (VULNERABLE, CONTROL):
            actual_image_id = evidence["images"][arm["arm"]].get("image_id")
            if actual_image_id != arm["image_id"]:
                raise RuntimeError(
                    f"The exact local {arm['arm']} image ID was not available."
                )
        docker.run(
            "network",
            "create",
            "--label",
            f"{EXPERIMENT_LABEL}={experiment_id}",
            network_name,
        )
        for arm, container_name in (
            (VULNERABLE, vulnerable_name),
            (CONTROL, control_name),
        ):
            print(f"Running {arm['arm']} arm ({arm['image_reference']})...")
            evidence["arms"][arm["arm"]] = run_arm(
                docker,
                arm=arm,
                container_name=container_name,
                network_name=network_name,
                runtime_directory=runtime_directory,
                experiment_id=experiment_id,
                credentials=credentials,
                topic=topic,
            )
    except Exception as exc:
        evidence["fatal_error"] = f"{type(exc).__name__}: {exc}"
    finally:
        cleanup_checks = cleanup_temporary_resources(
            docker,
            container_names=[vulnerable_name, control_name],
            network_name=network_name,
            experiment_id=experiment_id,
            runtime_directory=runtime_directory,
        )
        baseline_after = capture_existing_baseline_states(docker)
        baseline_unchanged = baseline_before == baseline_after
        cleanup_checks["existing_baselines_unchanged"] = baseline_unchanged
        evidence["environment"]["baseline_deployment_states_after"] = baseline_after
        evidence["cleanup"] = cleanup_assessment(cleanup_checks)
        evidence["run_finished_utc"] = utc_now()

    if "vulnerable" not in evidence["arms"] or "control" not in evidence["arms"]:
        evidence["comparison"] = {
            "outcome": "INCONCLUSIVE",
            "supports_cve_broker_behaviour_reproduction": False,
            "summary": "One or both experimental arms did not execute.",
            "does_not_establish": [
                "target confidentiality, integrity or availability magnitude",
                "downstream Ditto or InfluxDB impact",
            ],
        }
    else:
        evidence["comparison"] = compare_arms(
            evidence["arms"]["vulnerable"],
            evidence["arms"]["control"],
        )
    evidence["limitations"] = [
        "This is one controlled retained-message/ACL transition, not an attack chain.",
        "Delivery does not establish a numerical confidentiality, integrity or availability consequence.",
        "Ditto and InfluxDB were not connected and no downstream impact was tested.",
        "QoS 1 delivery is not treated as proof of permission; ACL denial was checked separately.",
        "The control result applies only with check_retain_source=true and the recorded topic/ACL configuration.",
        "The historical CVE-2018-12546 observation remains MANUALLY_OBSERVED; this run is separate evidence.",
    ]
    comparison_ok = evidence["comparison"]["outcome"] in (
        "PAIRED_DIFFERENCE_OBSERVED",
        "NO_CONFIGURED_CONTROL_EFFECT_OBSERVED",
        "VULNERABLE_BEHAVIOUR_NOT_REPRODUCED",
    )
    cleanup_ok = evidence["cleanup"]["outcome"] == "VERIFIED"
    evidence["result"] = (
        "COMPLETED"
        if comparison_ok and cleanup_ok
        else "CLEANUP_FAILED"
        if cleanup_ok is False
        else "EXPERIMENT_FAILED"
    )
    write_evidence(evidence_path, evidence)
    print_terminal_summary(evidence, evidence_path)
    if not comparison_ok:
        return 1
    return evidence["cleanup"]["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
