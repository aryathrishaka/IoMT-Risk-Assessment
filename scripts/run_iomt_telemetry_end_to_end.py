"""Run one controlled Mosquitto -> Ditto -> InfluxDB telemetry test."""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
from urllib.parse import quote, unquote, urlsplit

import requests
from requests.auth import HTTPBasicAuth

from resume_ditto_influx_validation import (
    EXISTING_BUCKET,
    INFLUX_URL,
    request_checked,
    wait_for_writer,
)
from run_ditto_influx_validation import (
    BASE_URL,
    CONNECTION_TEMPLATE,
    OUTPUT_DIR,
    PRIVATE_ROOT,
    WRITER_HOST,
    WRITER_PORT,
    WRITER_SCRIPT,
    close_connection,
    devops_password,
    restrict_path,
    utc_now,
    wait_for_connection_open,
)
from run_mosquitto_ditto_dataflow import (
    mqtt_publish_qos1,
    wait_for_port,
)


MQTT_CONNECTION_ID = "709e3efe-3c62-4e41-9538-dc5316c43efd"
MQTT_TOPIC = "iomt/vuln-test"
BROKER_CONTAINER = "mosquitto-vuln-lab"
THING_FIELD = "temperature"
MARKER_FIELD = "runMarker"


def docker_command(*args: str, input_bytes: bytes | None = None):
    return subprocess.run(
        ["docker", *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def wait_for_thing_values(
    session: requests.Session,
    thing_id: str,
    marker: str,
    temperature: float,
    timeout_seconds: int = 20,
) -> dict:
    deadline = time.monotonic() + timeout_seconds
    last = {}
    while time.monotonic() < deadline:
        response = request_checked(
            session,
            "GET",
            f"{BASE_URL}/api/2/things/{thing_id}",
            expected=(200,),
        )
        last = response.json()
        attributes = last.get("attributes") or {}
        if (
            attributes.get(MARKER_FIELD) == marker
            and attributes.get(THING_FIELD) == temperature
        ):
            return last
        time.sleep(0.25)
    raise RuntimeError("Ditto did not expose the MQTT test values in the Thing.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bucket", default=EXISTING_BUCKET)
    parser.add_argument("--org", default="IoMT-Lab")
    args = parser.parse_args()

    ditto_password = getpass.getpass(
        "Enter the ordinary ditto nginx password: "
    )
    write_token = getpass.getpass(
        "Enter the write-only InfluxDB token for the test bucket: "
    )
    if not ditto_password or not write_token:
        print("Both hidden credentials are required.")
        return 2

    run_id = (
        "iomt-telemetry-e2e-"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    )
    suffix = uuid.uuid4().hex[:10]
    thing_id = f"iomt:e2e-mqtt-influx-{suffix}"
    policy_id = f"iomt:e2e-mqtt-influx-policy-{suffix}"
    event_connection_id = str(uuid.uuid4())
    marker = (
        f"E2E-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        f"-{suffix}"
    )
    temperature = 41.25

    runtime_dir = PRIVATE_ROOT / run_id
    runtime_dir.mkdir(parents=True, exist_ok=False)
    restrict_path(runtime_dir)
    acl_backup = runtime_dir / "aclfile.original"
    writer_config_path = runtime_dir / "writer-config.json"
    writer_state_path = runtime_dir / "writer-state.json"
    writer_log_path = runtime_dir / "writer.log"
    writer_error_path = runtime_dir / "writer.err.log"
    evidence_path = OUTPUT_DIR / f"{run_id}.json"

    ditto = requests.Session()
    ditto.trust_env = False
    ditto.auth = HTTPBasicAuth("ditto", ditto_password)

    devops = requests.Session()
    devops.trust_env = False
    devops.auth = HTTPBasicAuth("devops", devops_password())

    original_mqtt_connection = None
    original_mqtt_status = None
    event_connection_config = None
    event_connection_created = False
    mqtt_changed = False
    acl_changed = False
    writer_process = None
    thing_created = False
    policy_created = False
    initial_thing = None
    idle_thing = None
    final_thing = None
    restored_thing = None
    writer_state = None
    publish_result = None
    failure = None
    result = "FAILED"

    broker_uri = urlsplit(
        json.loads(
            (Path("vulnerable-ditto-connection.json")).read_text(
                encoding="utf-8"
            )
        )["uri"]
    )
    mqtt_username = unquote(broker_uri.username or "")
    mqtt_password = unquote(broker_uri.password or "")
    if not mqtt_username or not mqtt_password:
        print("The existing MQTT test credential is unavailable.")
        return 2

    flux_query = (
        f'from(bucket: "{args.bucket}")\n'
        "  |> range(start: -24h)\n"
        '  |> filter(fn: (r) => r._measurement == "ditto_thing_event")\n'
        '  |> filter(fn: (r) => r._field == "temperature")\n'
        f'  |> filter(fn: (r) => r.thing_id == "{thing_id}")\n'
        f'  |> filter(fn: (r) => r.run_marker == "{marker}")\n'
        "  |> last()\n"
        '  |> keep(columns: ["_time", "_value", "thing_id", "run_marker"])'
    )

    try:
        original_mqtt_connection = request_checked(
            devops,
            "GET",
            f"{BASE_URL}/api/2/connections/{MQTT_CONNECTION_ID}",
            expected=(200,),
        ).json()
        original_mqtt_status = request_checked(
            devops,
            "GET",
            f"{BASE_URL}/api/2/connections/{MQTT_CONNECTION_ID}/status",
            expected=(200,),
        ).json()
        if original_mqtt_status.get("liveStatus") != "closed":
            raise RuntimeError("The MQTT ingress connection was not initially closed.")

        copy_result = docker_command(
            "cp",
            f"{BROKER_CONTAINER}:/mosquitto/config/aclfile",
            str(acl_backup),
        )
        if copy_result.returncode != 0:
            raise RuntimeError("Unable to back up the broker ACL.")
        original_acl = acl_backup.read_bytes()
        if b"user sensoruser" not in original_acl:
            raise RuntimeError("The MQTT publisher user is absent from the ACL.")
        temporary_acl = original_acl
        if not temporary_acl.endswith((b"\n", b"\r")):
            temporary_acl += b"\n"
        temporary_acl += b"write " + MQTT_TOPIC.encode("ascii") + b"\n"
        staged_acl = runtime_dir / "aclfile.test"
        staged_acl.write_bytes(temporary_acl)
        copy_result = docker_command(
            "cp",
            str(staged_acl),
            f"{BROKER_CONTAINER}:/mosquitto/config/aclfile",
        )
        if copy_result.returncode != 0:
            raise RuntimeError("Unable to apply the temporary broker ACL.")
        acl_changed = True
        restart_result = docker_command("restart", BROKER_CONTAINER)
        if restart_result.returncode != 0 or not wait_for_port("127.0.0.1", 1884):
            raise RuntimeError("The vulnerable broker did not restart.")

        policy = {
            "policyId": policy_id,
            "entries": {
                "DEFAULT": {
                    "subjects": {
                        "nginx:ditto": {"type": "generated"},
                        "ditto:inbound-auth-subject": {
                            "type": "generated"
                        },
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

        writer_config = {
            "listen_host": "0.0.0.0",
            "listen_port": WRITER_PORT,
            "influx_url": INFLUX_URL,
            "influx_org": args.org,
            "influx_bucket": args.bucket,
            "expected_thing_id": thing_id,
            "state_file": str(writer_state_path),
        }
        writer_config_path.write_text(
            json.dumps(writer_config, indent=2) + "\n",
            encoding="utf-8",
        )

        event_connection_config = json.loads(
            CONNECTION_TEMPLATE.read_text(encoding="utf-8")
        )
        event_connection_config["id"] = event_connection_id
        event_connection_config["uri"] = (
            f"http://{WRITER_HOST}:{WRITER_PORT}"
        )
        event_connection_config["connectionStatus"] = "closed"
        request_checked(
            devops,
            "PUT",
            f"{BASE_URL}/api/2/connections/{event_connection_id}",
            expected=(200, 201, 204),
            json=event_connection_config,
        )
        event_connection_created = True

        with writer_log_path.open("wb") as output, writer_error_path.open(
            "wb"
        ) as error:
            writer_process = subprocess.Popen(
                [
                    sys.executable,
                    str(WRITER_SCRIPT),
                    "--config",
                    str(writer_config_path),
                    "--token-stdin",
                ],
                stdin=subprocess.PIPE,
                stdout=output,
                stderr=error,
            )
            writer_process.stdin.write((write_token + "\n").encode("utf-8"))
            writer_process.stdin.flush()
            writer_process.stdin.close()
        if not wait_for_writer():
            raise RuntimeError("The InfluxDB event writer did not become ready.")

        event_connection_config["connectionStatus"] = "open"
        request_checked(
            devops,
            "PUT",
            f"{BASE_URL}/api/2/connections/{event_connection_id}",
            expected=(200, 201, 204),
            json=event_connection_config,
        )
        wait_for_connection_open(devops, event_connection_id)

        modified_mqtt = copy.deepcopy(original_mqtt_connection)
        modified_mqtt["uri"] = (
            "tcp://"
            + quote(mqtt_username, safe="")
            + ":"
            + quote(mqtt_password, safe="")
            + f"@{broker_uri.hostname}:{broker_uri.port or 1883}"
        )
        modified_mqtt["connectionStatus"] = "open"
        request_checked(
            devops,
            "PUT",
            f"{BASE_URL}/api/2/connections/{MQTT_CONNECTION_ID}",
            expected=(200, 204),
            json=modified_mqtt,
        )
        mqtt_changed = True
        wait_for_connection_open(devops, MQTT_CONNECTION_ID)

        initial_thing = request_checked(
            ditto,
            "GET",
            f"{BASE_URL}/api/2/things/{thing_id}",
            expected=(200,),
        ).json()
        idle_started = utc_now()
        time.sleep(5)
        idle_thing = request_checked(
            ditto,
            "GET",
            f"{BASE_URL}/api/2/things/{thing_id}",
            expected=(200,),
        ).json()
        idle_finished = utc_now()
        if initial_thing.get("attributes") != idle_thing.get("attributes"):
            raise RuntimeError("The isolated Thing changed during the idle window.")

        payload = {
            "topic": (
                f"{thing_id.replace(':', '/', 1)}"
                "/things/twin/commands/modify"
            ),
            "headers": {},
            "path": "/attributes",
            "value": {
                "temperature": temperature,
                "runMarker": marker,
            },
        }
        publish_result = mqtt_publish_qos1(
            "127.0.0.1",
            1884,
            mqtt_username,
            mqtt_password,
            MQTT_TOPIC,
            json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        )

        final_thing = wait_for_thing_values(
            ditto,
            thing_id,
            marker,
            temperature,
        )
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
        if writer_state.get("influx_http_status") != 204:
            raise RuntimeError("InfluxDB did not accept the writer request.")

        result = "WRITE_CONFIRMED_READBACK_PENDING"
    except Exception as exc:
        failure = f"{type(exc).__name__}: {exc}"
    finally:
        if event_connection_created and event_connection_config is not None:
            try:
                close_connection(
                    devops,
                    event_connection_id,
                    event_connection_config,
                )
            except Exception:
                pass

        if mqtt_changed and original_mqtt_connection is not None:
            try:
                restored_mqtt = copy.deepcopy(original_mqtt_connection)
                restored_mqtt["connectionStatus"] = "closed"
                request_checked(
                    devops,
                    "PUT",
                    f"{BASE_URL}/api/2/connections/{MQTT_CONNECTION_ID}",
                    expected=(200, 204),
                    json=restored_mqtt,
                )
            except Exception:
                pass

        if thing_created and initial_thing is not None:
            try:
                request_checked(
                    ditto,
                    "PUT",
                    f"{BASE_URL}/api/2/things/{thing_id}/attributes",
                    expected=(200, 201, 204),
                    json=initial_thing["attributes"],
                )
                restored_thing = request_checked(
                    ditto,
                    "GET",
                    f"{BASE_URL}/api/2/things/{thing_id}",
                    expected=(200,),
                ).json()
            except Exception:
                restored_thing = None

        if writer_process is not None:
            writer_process.terminate()
            try:
                writer_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                writer_process.kill()
                writer_process.wait(timeout=5)

        if acl_changed:
            try:
                docker_command(
                    "cp",
                    str(acl_backup),
                    f"{BROKER_CONTAINER}:/mosquitto/config/aclfile",
                )
                docker_command("restart", BROKER_CONTAINER)
                wait_for_port("127.0.0.1", 1884)
            except Exception:
                pass

        if event_connection_created:
            try:
                devops.delete(
                    f"{BASE_URL}/api/2/connections/{event_connection_id}",
                    timeout=20,
                )
            except Exception:
                pass

        writer_stopped = writer_process is not None and (
            writer_process.poll() is not None
        )
        thing_restored = (
            restored_thing is not None
            and (restored_thing.get("attributes") or {})
            == (initial_thing or {}).get("attributes")
        )

        evidence = {
            "schema_version": "1.0",
            "run_id": run_id,
            "collected_at_utc": utc_now(),
            "result": result,
            "failure": failure,
            "scope": (
                "One controlled MQTT-sourced Mosquitto to Ditto to "
                "InfluxDB telemetry path"
            ),
            "configuration": {
                "mqtt_connection_id": MQTT_CONNECTION_ID,
                "mqtt_source_topic": MQTT_TOPIC,
                "thing_id": thing_id,
                "policy_id": policy_id,
                "influx_event_connection_id": event_connection_id,
                "influx_bucket": args.bucket,
                "influx_org": args.org,
                "writer_influx_health_url": f"{INFLUX_URL}/health",
            },
            "test": {
                "initial_thing": initial_thing,
                "idle_started_utc": idle_started
                if "idle_started" in locals()
                else None,
                "idle_finished_utc": idle_finished
                if "idle_finished" in locals()
                else None,
                "idle_thing": idle_thing,
                "run_marker": marker,
                "numeric_temperature": temperature,
                "mqtt_payload": payload if "payload" in locals() else None,
                "broker_acknowledgement": publish_result,
                "thing_readback": final_thing,
                "writer_event": writer_state,
            },
            "verification": {
                "broker_acknowledged": publish_result is not None,
                "ditto_thing_updated": final_thing is not None,
                "writer_received_event": writer_state is not None,
                "influx_write_http_status": (
                    writer_state.get("influx_http_status")
                    if writer_state
                    else None
                ),
                "thing_id_matches_writer": (
                    final_thing.get("thingId")
                    == writer_state.get("thing_id")
                    if final_thing and writer_state
                    else False
                ),
                "temperature_matches_writer": (
                    (final_thing.get("attributes") or {}).get(
                        "temperature"
                    )
                    == writer_state.get("temperature")
                    if final_thing and writer_state
                    else False
                ),
                "marker_matches_writer": (
                    (final_thing.get("attributes") or {}).get(
                        "runMarker"
                    )
                    == writer_state.get("run_marker")
                    if final_thing and writer_state
                    else False
                ),
                "readback_status": "PENDING_USER_CONFIRMATION",
                "readback_query": flux_query,
            },
            "cleanup": {
                "thing_restored": thing_restored,
                "thing_retained": thing_created,
                "policy_retained": policy_created,
                "event_connection_deleted": event_connection_created,
                "mqtt_connection_restored": mqtt_changed,
                "writer_stopped": writer_stopped,
            },
            "credential_handling": {
                "credentials_recorded": False,
                "tokens_recorded": False,
                "authorization_headers_recorded": False,
                "private_runtime_directory": str(runtime_dir),
            },
            "assessment_boundary": (
                "This establishes only the controlled normal MQTT-sourced "
                "data path through Ditto into InfluxDB. It does not establish "
                "vulnerability exploitation, attack feasibility or adverse "
                "C/I/A impact."
            ),
        }
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(
            json.dumps(evidence, indent=2) + "\n",
            encoding="utf-8",
        )
        ditto_password = ""
        write_token = ""
        mqtt_password = ""
        ditto.close()
        devops.close()

        print(f"RESULT={result}")
        print(f"THING_ID={thing_id}")
        print(f"MARKER={marker}")
        print(f"TEMPERATURE={temperature}")
        print(
            "BROKER_PUBACK="
            f"{(publish_result or {}).get('puback_received_utc')}"
        )
        print(f"WRITER_RECEIVED={writer_state is not None}")
        print(
            "INFLUX_HTTP="
            f"{(writer_state or {}).get('influx_http_status')}"
        )
        print(f"THING_RESTORED={thing_restored}")
        print(f"EVIDENCE={evidence_path}")
        print("FLUX_QUERY_BEGIN")
        print(flux_query)
        print("FLUX_QUERY_END")

    return 0 if result == "WRITE_CONFIRMED_READBACK_PENDING" else 1


if __name__ == "__main__":
    raise SystemExit(main())
