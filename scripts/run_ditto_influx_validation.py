"""Create and validate one isolated Ditto event to InfluxDB telemetry link."""

from __future__ import annotations

import argparse
import copy
import csv
from datetime import datetime, timezone
import getpass
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import requests
from requests.auth import HTTPBasicAuth


ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "http://localhost:8080"
INFLUX_URL = "http://localhost:8086"
WRITER_SCRIPT = ROOT / "lab" / "ditto_influx_telemetry" / "writer.py"
CONNECTION_TEMPLATE = (
    ROOT / "lab" / "ditto_influx_telemetry" / "connection.template.json"
)
PRIVATE_ROOT = (
    Path(os.environ["LOCALAPPDATA"])
    / "IoMT-Lab-Backups"
    / "DittoInfluxTelemetry"
)
OUTPUT_DIR = ROOT / "output" / "evidence_runs"
WRITER_HOST = "host.docker.internal"
WRITER_PORT = 8095


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def docker_json(*args: str):
    completed = subprocess.run(
        ["docker", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"Docker command failed: docker {' '.join(args)}")
    return json.loads(completed.stdout.decode("utf-8"))


def restrict_path(path: Path) -> None:
    user = os.environ.get("USERNAME") or os.getlogin()
    subprocess.run(
        [
            "icacls",
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"{user}:(OI)(CI)F",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
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
        raise RuntimeError(
            f"{method} {url} returned HTTP {response.status_code}."
        )
    return response


def devops_password() -> str:
    environment = docker_json(
        "inspect",
        "docker-gateway-1",
        "--format",
        "{{json .Config.Env}}",
    )
    entry = next(
        (
            item
            for item in environment
            if item.startswith("DEVOPS_PASSWORD=")
        ),
        None,
    )
    if not entry:
        raise RuntimeError("The local DevOps credential is unavailable.")
    return entry.split("=", 1)[1]


def wait_for_writer(timeout_seconds: int = 20) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            response = requests.get(
                f"http://127.0.0.1:{WRITER_PORT}/health",
                timeout=1,
            )
            if response.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(0.25)
    return False


def wait_for_connection_open(
    devops: requests.Session,
    connection_id: str,
    timeout_seconds: int = 20,
) -> dict:
    deadline = time.monotonic() + timeout_seconds
    last = {}
    while time.monotonic() < deadline:
        response = request_checked(
            devops,
            "GET",
            f"{BASE_URL}/api/2/connections/{connection_id}/status",
            expected=(200,),
        )
        last = response.json()
        if last.get("liveStatus") == "open":
            return last
        time.sleep(0.5)
    raise RuntimeError(f"The test connection did not open: {last.get('liveStatus')}")


def close_connection(
    devops: requests.Session,
    connection_id: str,
    connection_config: dict,
) -> None:
    closed = copy.deepcopy(connection_config)
    closed["connectionStatus"] = "closed"
    request_checked(
        devops,
        "PUT",
        f"{BASE_URL}/api/2/connections/{connection_id}",
        expected=(200, 204),
        json=closed,
    )
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        response = request_checked(
            devops,
            "GET",
            f"{BASE_URL}/api/2/connections/{connection_id}/status",
            expected=(200,),
        )
        if response.json().get("liveStatus") == "closed":
            return
        time.sleep(0.5)
    raise RuntimeError("The test connection did not return to closed.")


def flux_query(
    session: requests.Session,
    org_id: str,
    bucket: str,
    thing_id: str,
    marker: str,
) -> dict | None:
    query = f'''
from(bucket: "{bucket}")
  |> range(start: -30m)
  |> filter(fn: (r) => r._measurement == "ditto_thing_event")
  |> filter(fn: (r) => r._field == "temperature")
  |> filter(fn: (r) => r.thing_id == "{thing_id}")
  |> filter(fn: (r) => r.run_marker == "{marker}")
  |> last()
'''
    response = request_checked(
        session,
        "POST",
        f"{INFLUX_URL}/api/v2/query",
        expected=(200,),
        params={"orgID": org_id},
        headers={
            "Content-Type": "application/vnd.flux",
            "Accept": "application/csv",
        },
        data=query.encode("utf-8"),
    )
    lines = [
        line
        for line in response.text.splitlines()
        if not line.startswith("#")
    ]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    for row in reader:
        if row.get("_value"):
            return row
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--leave-running",
        action="store_true",
        help="Leave the writer and Ditto connection open after validation.",
    )
    args = parser.parse_args()

    ditto_password = getpass.getpass(
        "Enter the ordinary ditto nginx password: "
    )
    influx_admin_token = getpass.getpass(
        "Enter the InfluxDB administrator token: "
    )
    if not ditto_password or not influx_admin_token:
        print("Both hidden credentials are required.")
        return 2

    run_id = (
        "ditto-influx-telemetry-"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    )
    suffix = uuid.uuid4().hex[:10]
    thing_id = f"iomt:ditto-influx-test-{suffix}"
    policy_id = f"iomt:ditto-influx-policy-{suffix}"
    bucket = f"iomt-ditto-influx-test-{suffix}"
    connection_id = str(uuid.uuid4())
    marker = f"DI-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{suffix}"
    temperature = 39.25

    runtime_dir = PRIVATE_ROOT / run_id
    runtime_dir.mkdir(parents=True, exist_ok=False)
    restrict_path(runtime_dir)
    write_token_file = runtime_dir / "influx-write-token"
    read_token_file = runtime_dir / "influx-read-token"
    writer_config_path = runtime_dir / "writer-config.json"
    writer_state_path = runtime_dir / "writer-state.json"
    writer_log_path = runtime_dir / "writer.log"
    writer_error_path = runtime_dir / "writer.err.log"
    link_config_path = runtime_dir / "link-config.json"
    evidence_path = OUTPUT_DIR / f"{run_id}.json"

    ditto = requests.Session()
    ditto.trust_env = False
    ditto.auth = HTTPBasicAuth("ditto", ditto_password)

    devops = requests.Session()
    devops.trust_env = False
    devops.auth = HTTPBasicAuth("devops", devops_password())

    influx_admin = requests.Session()
    influx_admin.trust_env = False
    influx_admin.headers.update(
        {"Authorization": f"Token {influx_admin_token}"}
    )

    writer_process = None
    connection_created = False
    connection_config = None
    bucket_created = False
    policy_created = False
    thing_created = False
    result = "FAILED"
    failure = None
    writer_state = None
    influx_row = None
    thing_before = None
    thing_after = None
    comparison = {}
    final_writer_running = None
    final_connection_status = None
    write_auth = None
    read_auth = None
    org = None

    try:
        orgs = request_checked(
            influx_admin,
            "GET",
            f"{INFLUX_URL}/api/v2/orgs",
            expected=(200,),
        ).json().get("orgs", [])
        if not orgs:
            raise RuntimeError("No InfluxDB organization is available.")
        org = orgs[0]

        bucket_response = request_checked(
            influx_admin,
            "POST",
            f"{INFLUX_URL}/api/v2/buckets",
            expected=(201,),
            json={
                "orgID": org["id"],
                "name": bucket,
                "description": f"Isolated Ditto telemetry validation {run_id}",
                "retentionRules": [
                    {
                        "type": "expire",
                        "everySeconds": 604800,
                        "shardGroupDurationSeconds": 86400,
                    }
                ],
            },
        ).json()
        bucket_created = True

        write_auth = request_checked(
            influx_admin,
            "POST",
            f"{INFLUX_URL}/api/v2/authorizations",
            expected=(201,),
            json={
                "orgID": org["id"],
                "description": f"Write-only token for {run_id}",
                "permissions": [
                    {
                        "action": "write",
                        "resource": {
                            "type": "buckets",
                            "id": bucket_response["id"],
                        },
                    }
                ],
            },
        ).json()
        read_auth = request_checked(
            influx_admin,
            "POST",
            f"{INFLUX_URL}/api/v2/authorizations",
            expected=(201,),
            json={
                "orgID": org["id"],
                "description": f"Read-only token for {run_id}",
                "permissions": [
                    {
                        "action": "read",
                        "resource": {
                            "type": "buckets",
                            "id": bucket_response["id"],
                        },
                    }
                ],
            },
        ).json()
        write_token_file.write_text(write_auth["token"], encoding="utf-8")
        read_token_file.write_text(read_auth["token"], encoding="utf-8")
        restrict_path(write_token_file)
        restrict_path(read_token_file)

        policy = {
            "policyId": policy_id,
            "entries": {
                "DEFAULT": {
                    "subjects": {
                        "nginx:ditto": {"type": "generated"},
                        "ditto:outbound-auth-subject": {
                            "type": "generated"
                        },
                    },
                    "resources": {
                        "thing:/": {
                            "grant": ["READ", "WRITE"],
                            "revoke": [],
                        },
                        "message:/": {
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
        request_checked(
            ditto,
            "PUT",
            f"{BASE_URL}/api/2/policies/{policy_id}",
            expected=(200, 201, 204),
            json=policy,
        )
        policy_created = True

        initial_thing = {
            "thingId": thing_id,
            "policyId": policy_id,
            "attributes": {
                "temperature": 37.0,
                "runMarker": "BASELINE",
            },
        }
        request_checked(
            ditto,
            "PUT",
            f"{BASE_URL}/api/2/things/{thing_id}",
            expected=(200, 201, 204),
            json=initial_thing,
        )
        thing_created = True
        thing_before = request_checked(
            ditto,
            "GET",
            f"{BASE_URL}/api/2/things/{thing_id}",
            expected=(200,),
        ).json()

        writer_config = {
            "listen_host": "0.0.0.0",
            "listen_port": WRITER_PORT,
            "influx_url": INFLUX_URL,
            "influx_org_id": org["id"],
            "influx_bucket": bucket,
            "influx_token_file": str(write_token_file),
            "expected_thing_id": thing_id,
            "state_file": str(writer_state_path),
        }
        writer_config_path.write_text(
            json.dumps(writer_config, indent=2) + "\n",
            encoding="utf-8",
        )

        connection_config = json.loads(
            CONNECTION_TEMPLATE.read_text(encoding="utf-8")
        )
        connection_config["id"] = connection_id
        connection_config["uri"] = (
            f"http://{WRITER_HOST}:{WRITER_PORT}"
        )
        connection_config["connectionStatus"] = "closed"
        request_checked(
            devops,
            "PUT",
            f"{BASE_URL}/api/2/connections/{connection_id}",
            expected=(200, 201, 204),
            json=connection_config,
        )
        connection_created = True

        with writer_log_path.open("wb") as output, writer_error_path.open(
            "wb"
        ) as error:
            writer_process = subprocess.Popen(
                [
                    sys.executable,
                    str(WRITER_SCRIPT),
                    "--config",
                    str(writer_config_path),
                ],
                stdout=output,
                stderr=error,
            )
        if not wait_for_writer():
            raise RuntimeError("The local Ditto event writer did not become ready.")

        connection_config["connectionStatus"] = "open"
        request_checked(
            devops,
            "PUT",
            f"{BASE_URL}/api/2/connections/{connection_id}",
            expected=(200, 201, 204),
            json=connection_config,
        )
        connection_status = wait_for_connection_open(
            devops,
            connection_id,
        )

        update_started = utc_now()
        request_checked(
            ditto,
            "PUT",
            f"{BASE_URL}/api/2/things/{thing_id}/attributes",
            expected=(200, 201, 204),
            json={
                "temperature": temperature,
                "runMarker": marker,
            },
        )
        update_completed = utc_now()
        thing_after = request_checked(
            ditto,
            "GET",
            f"{BASE_URL}/api/2/things/{thing_id}",
            expected=(200,),
        ).json()

        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if writer_state_path.exists():
                candidate = json.loads(
                    writer_state_path.read_text(encoding="utf-8")
                )
                if candidate.get("run_marker") == marker:
                    writer_state = candidate
                    break
            time.sleep(0.25)
        if writer_state is None:
            raise RuntimeError("The writer did not record the Ditto event.")

        influx_read = requests.Session()
        influx_read.trust_env = False
        influx_read.headers.update(
            {
                "Authorization": (
                    "Token "
                    + read_token_file.read_text(encoding="utf-8").strip()
                )
            }
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            influx_row = flux_query(
                influx_read,
                org["id"],
                bucket,
                thing_id,
                marker,
            )
            if influx_row is not None:
                break
            time.sleep(0.5)
        if influx_row is None:
            raise RuntimeError("The marker was not found in InfluxDB.")

        attrs = thing_after.get("attributes") or {}
        thing_modified = (
            thing_after.get("_modified")
            or thing_after.get("_created")
        )
        writer_received = writer_state["received_at_utc"]
        influx_time = influx_row["_time"]
        timestamp_delta_seconds = (
            parse_utc(writer_received) - parse_utc(thing_modified)
        ).total_seconds()
        influx_delta_seconds = abs(
            (
                parse_utc(influx_time) - parse_utc(writer_received)
            ).total_seconds()
        )
        influx_temperature = float(influx_row["_value"])
        comparison = {
            "thing_id_match": (
                writer_state["thing_id"] == thing_id
                and influx_row.get("thing_id") == thing_id
            ),
            "temperature_match": (
                attrs.get("temperature") == temperature
                and writer_state["temperature"] == temperature
                and influx_temperature == temperature
            ),
            "marker_match": (
                attrs.get("runMarker") == marker
                and writer_state["run_marker"] == marker
                and influx_row.get("run_marker") == marker
            ),
            "thing_modified_utc": thing_modified,
            "writer_received_utc": writer_received,
            "influx_point_utc": influx_time,
            "thing_to_writer_delta_seconds": timestamp_delta_seconds,
            "writer_to_influx_delta_seconds": influx_delta_seconds,
            "timestamps_consistent": (
                0 <= timestamp_delta_seconds <= 15
                and influx_delta_seconds <= 5
            ),
        }
        if not all(
            comparison[key]
            for key in (
                "thing_id_match",
                "temperature_match",
                "marker_match",
                "timestamps_consistent",
            )
        ):
            raise RuntimeError("The Ditto, writer and InfluxDB values disagree.")

        result = "VALIDATED"
        link_config = {
            "run_id": run_id,
            "thing_id": thing_id,
            "policy_id": policy_id,
            "connection_id": connection_id,
            "connection_config": connection_config,
            "writer_config_path": str(writer_config_path),
            "writer_state_path": str(writer_state_path),
            "writer_log_path": str(writer_log_path),
            "writer_error_path": str(writer_error_path),
            "bucket": bucket,
            "org_id": org["id"],
            "bucket_id": bucket_response["id"],
            "write_token_file": str(write_token_file),
            "read_token_file": str(read_token_file),
            "latest_observation": {
                "run_marker": marker,
                "temperature": temperature,
                "connection_status_at_validation": connection_status,
            },
        }
    except Exception as exc:
        failure = f"{type(exc).__name__}: {exc}"
    finally:
        if connection_created and connection_config is not None:
            try:
                close_connection(devops, connection_id, connection_config)
                final_connection_status = "closed"
            except Exception:
                final_connection_status = "UNAVAILABLE"

        if writer_process is not None:
            writer_process.terminate()
            try:
                writer_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                writer_process.kill()
                writer_process.wait(timeout=5)
        final_writer_running = writer_process is not None and (
            writer_process.poll() is None
        )

        runtime = {
            "run_id": run_id,
            "thing_id": thing_id,
            "policy_id": policy_id,
            "connection_id": connection_id,
            "connection_config": connection_config,
            "writer_config_path": str(writer_config_path),
            "writer_state_path": str(writer_state_path),
            "writer_log_path": str(writer_log_path),
            "writer_error_path": str(writer_error_path),
            "bucket": bucket,
            "org_id": org["id"] if org else None,
            "write_token_file": str(write_token_file),
            "read_token_file": str(read_token_file),
        }
        link_config_path.write_text(
            json.dumps(runtime, indent=2) + "\n",
            encoding="utf-8",
        )

        evidence = {
            "schema_version": "1.0",
            "run_id": run_id,
            "collected_at_utc": utc_now(),
            "result": result,
            "failure": failure,
            "scope": (
                "Isolated Ditto-emitted Thing event to InfluxDB telemetry "
                "second hop"
            ),
            "configuration": {
                "ditto_connection_id": connection_id,
                "ditto_connection_type": "http-push",
                "ditto_target_topic": "_/_/things/twin/events",
                "writer_endpoint": f"http://{WRITER_HOST}:{WRITER_PORT}/events",
                "thing_id": thing_id,
                "policy_id": policy_id,
                "influx_org_id": org["id"] if org else None,
                "influx_bucket": bucket,
                "bucket_created": bucket_created,
                "policy_created": policy_created,
                "thing_created": thing_created,
                "token_scopes": {
                    "writer": ["write:bucket"],
                    "verification": ["read:bucket"],
                },
            },
            "test": {
                "thing_before": thing_before,
                "thing_after": thing_after,
                "run_marker": marker,
                "numeric_temperature": temperature,
                "update_started_utc": update_started
                if "update_started" in locals()
                else None,
                "update_completed_utc": update_completed
                if "update_completed" in locals()
                else None,
                "writer_event": writer_state,
                "influx_row": influx_row,
            },
            "comparison": comparison,
            "cleanup": {
                "connection_final_status": final_connection_status,
                "writer_stopped": final_writer_running is False,
                "writer_process_running": final_writer_running,
                "dedicated_bucket_retained": bucket_created,
                "isolated_test_thing_retained": thing_created,
                "existing_v4_assessment_modified": False,
            },
            "credential_handling": {
                "credentials_recorded": False,
                "tokens_recorded": False,
                "authorization_headers_recorded": False,
                "private_runtime_directory": str(runtime_dir),
            },
            "assessment_boundary": (
                "This validates only the isolated normal Ditto event to "
                "InfluxDB telemetry path. It does not establish vulnerability "
                "exploitation, attack feasibility or adverse C/I/A impact."
            ),
        }
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(
            json.dumps(evidence, indent=2) + "\n",
            encoding="utf-8",
        )

        ditto_password = ""
        influx_admin_token = ""
        ditto.close()
        devops.close()
        influx_admin.close()

        print(f"RESULT={result}")
        print(f"THING_ID={thing_id}")
        print(f"RUN_MARKER={marker}")
        print(f"TEMPERATURE={temperature}")
        print(f"CONNECTION_STATUS={final_connection_status}")
        print(f"WRITER_STOPPED={final_writer_running is False}")
        print(f"EVIDENCE={evidence_path}")
        print(f"RUNTIME_CONFIG={link_config_path}")

    return 0 if result == "VALIDATED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
