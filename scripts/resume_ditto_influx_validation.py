"""Validate Ditto event delivery to a pre-existing InfluxDB test bucket.

This variant uses a write-only token, writes one point, and leaves InfluxDB
readback pending for the operator to confirm through Data Explorer.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import requests
from requests.auth import HTTPBasicAuth

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
    parse_utc,
    request_checked,
    restrict_path,
    utc_now,
    wait_for_connection_open,
    wait_for_writer,
)


INFLUX_URL = "http://127.0.0.1:8086"
EXISTING_BUCKET = "iomt-ditto-influx-test-cd1c965d2a"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bucket", default=EXISTING_BUCKET)
    parser.add_argument("--org")
    parser.add_argument("--cleanup-config")
    args = parser.parse_args()

    ditto_password = getpass.getpass(
        "Enter the ordinary ditto nginx password: "
    )
    write_token = getpass.getpass(
        "Enter the write-only InfluxDB token for the test bucket: "
    )
    org_name = args.org or input("Enter the InfluxDB organisation name: ").strip()
    if not ditto_password or not write_token or not org_name:
        print("The Ditto password, write token and organisation are required.")
        return 2

    run_id = (
        "ditto-influx-resume-"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    )
    suffix = uuid.uuid4().hex[:10]
    thing_id = f"iomt:ditto-influx-resume-{suffix}"
    policy_id = f"iomt:ditto-influx-resume-policy-{suffix}"
    connection_id = str(uuid.uuid4())
    marker = (
        f"DI-RESUME-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        f"-{suffix}"
    )
    temperature = 40.75

    runtime_dir = PRIVATE_ROOT / run_id
    runtime_dir.mkdir(parents=True, exist_ok=False)
    restrict_path(runtime_dir)
    writer_config_path = runtime_dir / "writer-config.json"
    writer_state_path = runtime_dir / "writer-state.json"
    writer_log_path = runtime_dir / "writer.log"
    writer_error_path = runtime_dir / "writer.err.log"
    link_config_path = runtime_dir / "link-config.json"

    ditto = requests.Session()
    ditto.trust_env = False
    ditto.auth = HTTPBasicAuth("ditto", ditto_password)

    devops = requests.Session()
    devops.trust_env = False
    devops.auth = HTTPBasicAuth("devops", devops_password())

    writer_process = None
    connection_config = None
    connection_created = False
    policy_created = False
    thing_created = False
    update_started = None
    update_completed = None
    writer_ready = False
    thing_before = None
    thing_after = None
    restored_thing = None
    writer_state = None
    final_connection_status = None
    final_writer_running = None
    failure = None
    result = "FAILED"
    prior_cleanup = {}
    evidence_path = OUTPUT_DIR / f"{run_id}.json"
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
        if args.cleanup_config:
            cleanup_config = json.loads(
                Path(args.cleanup_config).read_text(encoding="utf-8")
            )
            prior_connection_id = cleanup_config.get("connection_id")
            prior_thing_id = cleanup_config.get("thing_id")
            prior_policy_id = cleanup_config.get("policy_id")
            if prior_connection_id:
                response = devops.delete(
                    f"{BASE_URL}/api/2/connections/{prior_connection_id}",
                    timeout=20,
                )
                prior_cleanup["connection"] = (
                    "DELETED"
                    if response.status_code in (200, 204)
                    else "NOT_FOUND"
                    if response.status_code == 404
                    else f"HTTP_{response.status_code}"
                )
            if prior_thing_id:
                response = ditto.delete(
                    f"{BASE_URL}/api/2/things/{prior_thing_id}",
                    timeout=20,
                )
                prior_cleanup["thing"] = (
                    "DELETED"
                    if response.status_code in (200, 204)
                    else "NOT_FOUND"
                    if response.status_code == 404
                    else f"HTTP_{response.status_code}"
                )
            if prior_policy_id:
                response = ditto.delete(
                    f"{BASE_URL}/api/2/policies/{prior_policy_id}",
                    timeout=20,
                )
                prior_cleanup["policy"] = (
                    "DELETED"
                    if response.status_code in (200, 204)
                    else "NOT_FOUND"
                    if response.status_code == 404
                    else f"HTTP_{response.status_code}"
                )
            prior_token = (
                Path(args.cleanup_config).parent
                / "influx-write-token"
            )
            if prior_token.exists():
                prior_token.unlink()
                prior_cleanup["token_file_removed"] = True
            else:
                prior_cleanup["token_file_removed"] = False

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
            "influx_org": org_name,
            "influx_bucket": args.bucket,
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
                    "--token-stdin",
                ],
                stdin=subprocess.PIPE,
                stdout=output,
                stderr=error,
            )
            writer_process.stdin.write(
                (write_token + "\n").encode("utf-8")
            )
            writer_process.stdin.flush()
            writer_process.stdin.close()
        if not wait_for_writer():
            raise RuntimeError("The event writer did not become ready.")
        writer_ready = True
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

        if writer_state.get("influx_http_status") != 204:
            raise RuntimeError("InfluxDB did not accept the writer request.")
        attributes = thing_after.get("attributes") or {}
        if (
            attributes.get("temperature") != temperature
            or attributes.get("runMarker") != marker
        ):
            raise RuntimeError("The isolated Thing does not match the event.")
        thing_modified = (
            thing_after.get("_modified")
            or thing_after.get("_created")
        )
        delta_seconds = None
        if thing_modified:
            delta_seconds = (
                parse_utc(writer_state["received_at_utc"])
                - parse_utc(thing_modified)
            ).total_seconds()
            if not 0 <= delta_seconds <= 15:
                raise RuntimeError(
                    "Thing and Ditto event timestamps are inconsistent."
                )

        result = "WRITE_CONFIRMED_READBACK_PENDING"
    except Exception as exc:
        failure = f"{type(exc).__name__}: {exc}"
    finally:
        if connection_created and connection_config is not None:
            try:
                close_connection(devops, connection_id, connection_config)
                final_connection_status = "closed"
            except Exception:
                final_connection_status = "UNAVAILABLE"

        if thing_created and thing_before is not None:
            try:
                request_checked(
                    ditto,
                    "PUT",
                    f"{BASE_URL}/api/2/things/{thing_id}/attributes",
                    expected=(200, 201, 204),
                    json=thing_before["attributes"],
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
        final_writer_running = writer_process is not None and (
            writer_process.poll() is None
        )
        writer_stopped = writer_process is not None and (
            writer_process.poll() is not None
        )
        thing_restored = (
            restored_thing is not None
            and (restored_thing.get("attributes") or {})
            == (thing_before or {}).get("attributes")
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
            "bucket": args.bucket,
            "influx_org": org_name,
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
                "One isolated Ditto event written to a pre-existing "
                "InfluxDB test bucket"
            ),
            "configuration": {
                "connection_id": connection_id,
                "connection_type": "http-push",
                "writer_endpoint": f"http://{WRITER_HOST}:{WRITER_PORT}/events",
                "writer_influx_health_url": f"{INFLUX_URL}/health",
                "writer_influx_health_required": 200,
                "thing_id": thing_id,
                "policy_id": policy_id,
                "influx_bucket": args.bucket,
                "influx_org": org_name,
                "bucket_created": False,
                "write_token_scope": "write-only bucket token",
                "admin_token_used": False,
                "read_token_used": False,
                "prior_temporary_resource_cleanup": prior_cleanup,
            },
            "test": {
                "thing_before": thing_before,
                "thing_after": thing_after,
                "thing_restored": restored_thing,
                "run_marker": marker,
                "numeric_temperature": temperature,
                "update_started_utc": update_started,
                "update_completed_utc": update_completed,
                "ditto_event": writer_state,
            },
            "verification": {
                "ditto_event_received": writer_state is not None,
                "writer_ready": writer_ready,
                "influx_write_http_status": (
                    writer_state.get("influx_http_status")
                    if writer_state
                    else None
                ),
                "thing_id_matches_event": (
                    (thing_after or {}).get("thingId")
                    == (writer_state or {}).get("thing_id")
                    if writer_state
                    else False
                ),
                "temperature_matches_event": (
                    ((thing_after or {}).get("attributes") or {}).get(
                        "temperature"
                    )
                    == (writer_state or {}).get("temperature")
                    if writer_state
                    else False
                ),
                "marker_matches_event": (
                    ((thing_after or {}).get("attributes") or {}).get(
                        "runMarker"
                    )
                    == (writer_state or {}).get("run_marker")
                    if writer_state
                    else False
                ),
                "thing_to_event_delta_seconds": delta_seconds
                if "delta_seconds" in locals()
                else None,
                "readback_status": "PENDING_USER_CONFIRMATION",
                "readback_query": flux_query,
            },
            "cleanup": {
                "connection_final_status": final_connection_status,
                "writer_stopped": writer_stopped,
                "writer_process_running": final_writer_running,
                "thing_restored": thing_restored,
                "isolated_thing_retained": thing_created,
                "isolated_policy_retained": policy_created,
                "existing_v4_modified": False,
            },
            "credential_handling": {
                "credentials_recorded": False,
                "tokens_recorded": False,
                "authorization_headers_recorded": False,
                "private_runtime_directory": str(runtime_dir),
            },
            "assessment_boundary": (
                "The write response and Ditto event correlation are established. "
                "InfluxDB readback remains pending until an authorised human "
                "confirms the Data Explorer query result."
            ),
        }
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(
            json.dumps(evidence, indent=2) + "\n",
            encoding="utf-8",
        )

        ditto_password = ""
        write_token = ""
        ditto.close()
        devops.close()

        print(f"RESULT={result}")
        print(f"THING_ID={thing_id}")
        print(f"RUN_MARKER={marker}")
        print(f"TEMPERATURE={temperature}")
        print(f"INFLUX_WRITE_HTTP={writer_state.get('influx_http_status') if writer_state else None}")
        print(f"CONNECTION_STATUS={final_connection_status}")
        print(f"WRITER_STOPPED={writer_stopped}")
        print(f"THING_RESTORED={thing_restored}")
        print(f"EVIDENCE={evidence_path}")
        print("FLUX_QUERY_BEGIN")
        print(flux_query)
        print("FLUX_QUERY_END")

    return 0 if result == "WRITE_CONFIRMED_READBACK_PENDING" else 1


if __name__ == "__main__":
    raise SystemExit(main())
