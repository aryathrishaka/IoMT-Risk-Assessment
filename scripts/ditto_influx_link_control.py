"""Start or stop the latest validated Ditto-to-InfluxDB telemetry link."""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import requests
from requests.auth import HTTPBasicAuth


ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "http://localhost:8080"
PRIVATE_ROOT = (
    Path(os.environ["LOCALAPPDATA"])
    / "IoMT-Lab-Backups"
    / "DittoInfluxTelemetry"
)
WRITER_SCRIPT = ROOT / "lab" / "ditto_influx_telemetry" / "writer.py"


def latest_config() -> Path:
    candidates = sorted(
        PRIVATE_ROOT.glob("*/link-config.json"),
        key=lambda path: path.stat().st_mtime,
    )
    if not candidates:
        raise RuntimeError("No validated Ditto-to-InfluxDB link is available.")
    return candidates[-1]


def get_devops_session() -> requests.Session:
    completed = subprocess.run(
        [
            "docker",
            "inspect",
            "docker-gateway-1",
            "--format",
            "{{json .Config.Env}}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("Unable to inspect the local Ditto gateway.")
    environment = json.loads(completed.stdout.decode("utf-8"))
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
    session = requests.Session()
    session.trust_env = False
    session.auth = HTTPBasicAuth("devops", entry.split("=", 1)[1])
    return session


def wait_for_writer(timeout_seconds: int = 20) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            response = requests.get(
                "http://127.0.0.1:8095/health",
                timeout=1,
            )
            if response.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(0.25)
    return False


def update_connection(
    session: requests.Session,
    connection_id: str,
    config: dict,
    status: str,
) -> None:
    updated = dict(config)
    updated["connectionStatus"] = status
    response = session.put(
        f"{BASE_URL}/api/2/connections/{connection_id}",
        json=updated,
        timeout=20,
    )
    if response.status_code not in (200, 204):
        raise RuntimeError(
            f"Unable to set connection status to {status}: "
            f"HTTP {response.status_code}."
        )


def connection_live_status(
    session: requests.Session,
    connection_id: str,
) -> str | None:
    response = session.get(
        f"{BASE_URL}/api/2/connections/{connection_id}/status",
        timeout=20,
    )
    if response.status_code != 200:
        return None
    return response.json().get("liveStatus")


def start(config_path: Path) -> int:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    runtime_dir = config_path.parent
    writer_config = Path(config["writer_config_path"])
    writer_pid_path = runtime_dir / "writer.pid"
    if not wait_for_writer(1):
        writer_config_value = json.loads(
            writer_config.read_text(encoding="utf-8")
        )
        token_stdin = not writer_config_value.get("influx_token_file")
        token = (
            getpass.getpass(
                "Enter the write-only InfluxDB token for the writer: "
            )
            if token_stdin
            else None
        )
        creation_flags = 0
        if os.name == "nt":
            creation_flags = (
                subprocess.DETACHED_PROCESS
                | subprocess.CREATE_NEW_PROCESS_GROUP
            )
        with Path(config["writer_log_path"]).open("ab") as output, Path(
            config["writer_error_path"]
        ).open("ab") as error:
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(WRITER_SCRIPT),
                    "--config",
                    str(writer_config),
                ],
                stdin=subprocess.PIPE if token_stdin else None,
                stdout=output,
                stderr=error,
                creationflags=creation_flags,
            )
        if token_stdin:
            process.stdin.write((token + "\n").encode("utf-8"))
            process.stdin.flush()
            process.stdin.close()
        writer_pid_path.write_text(str(process.pid), encoding="ascii")
        if not wait_for_writer():
            raise RuntimeError("The telemetry writer did not become ready.")

    devops = get_devops_session()
    try:
        update_connection(
            devops,
            config["connection_id"],
            config["connection_config"],
            "open",
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if connection_live_status(
                devops,
                config["connection_id"],
            ) == "open":
                print("WRITER_RUNNING=true")
                print("CONNECTION_STATUS=open")
                print(f"CONFIG={config_path}")
                return 0
            time.sleep(0.5)
        raise RuntimeError("The Ditto event connection did not become live.")
    finally:
        devops.close()


def stop(config_path: Path) -> int:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    runtime_dir = config_path.parent
    devops = get_devops_session()
    try:
        update_connection(
            devops,
            config["connection_id"],
            config["connection_config"],
            "closed",
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if connection_live_status(
                devops,
                config["connection_id"],
            ) == "closed":
                break
            time.sleep(0.5)
    finally:
        devops.close()

    pid_path = runtime_dir / "writer.pid"
    stopped = True
    if pid_path.exists():
        try:
            pid = int(pid_path.read_text(encoding="ascii").strip())
            os.kill(pid, signal.SIGTERM)
        except (OSError, ValueError):
            stopped = False
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and wait_for_writer(1):
            time.sleep(0.25)
        pid_path.unlink(missing_ok=True)
    print("CONNECTION_STATUS=closed")
    print(f"WRITER_STOPPED={str(stopped).lower()}")
    print(f"CONFIG={config_path}")
    return 0 if stopped else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("start", "stop"))
    parser.add_argument("--config")
    args = parser.parse_args()
    config_path = (
        Path(args.config) if args.config else latest_config()
    )
    return start(config_path) if args.action == "start" else stop(config_path)


if __name__ == "__main__":
    raise SystemExit(main())
