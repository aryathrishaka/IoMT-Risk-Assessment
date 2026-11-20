"""Small Ditto HTTP-push receiver that writes matching events to InfluxDB.

The service accepts only the configured test Thing and writes one InfluxDB
point for an event containing a numeric ``temperature`` and a ``runMarker``.
The InfluxDB token is read from a local file and is never logged.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import time
from urllib.parse import quote, urlsplit

import requests


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_thing_id(payload: dict) -> str | None:
    thing_id = payload.get("thingId")
    if isinstance(thing_id, str) and thing_id:
        return thing_id

    headers = payload.get("headers") or {}
    for key in ("thing-id", "thingId", "ditto-thing-id"):
        value = headers.get(key)
        if isinstance(value, str) and value:
            return value

    topic = payload.get("topic")
    if isinstance(topic, str) and "/things/" in topic:
        candidate = topic.split("/things/", 1)[0]
        if candidate.count("/") == 1 and ":" not in candidate:
            namespace, name = candidate.split("/", 1)
            return f"{namespace}:{name}"
        return candidate
    return None


def extract_values(payload: dict) -> tuple[object, str | None] | None:
    path = payload.get("path")
    value = payload.get("value")

    if path == "/attributes" and isinstance(value, dict):
        return value.get("temperature"), value.get("runMarker")

    if path == "/" and isinstance(value, dict):
        attributes = value.get("attributes") or {}
        return attributes.get("temperature"), attributes.get("runMarker")

    if path == "/attributes/temperature" and isinstance(value, (int, float)):
        return value, None

    return None


def escape_tag(value: object) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace(",", "\\,")
        .replace("=", "\\=")
        .replace(" ", "\\ ")
    )


def format_line_protocol(
    thing_id: str,
    marker: str,
    temperature: float,
    timestamp_ns: int,
) -> str:
    return (
        "ditto_thing_event"
        f",thing_id={escape_tag(thing_id)}"
        f",run_marker={escape_tag(marker)}"
        f" temperature={float(temperature):.12g}"
        f" {timestamp_ns}"
    )


class Writer:
    def __init__(self, config: dict, influx_token: str):
        self.config = config
        self.expected_thing_id = config["expected_thing_id"]
        self.influx_url = config["influx_url"].rstrip("/")
        self.influx_org = (
            config.get("influx_org")
            or config.get("influx_org_id")
        )
        self.influx_org_parameter = (
            "org"
            if config.get("influx_org")
            else "orgID"
        )
        self.influx_bucket = config["influx_bucket"]
        self.influx_token = influx_token
        self.state_file = Path(config["state_file"])
        self.lock = threading.Lock()
        self.http = requests.Session()
        self.http.trust_env = False
        self.last_accepted_at = None
        self.influx_health_status: int | None = None

    def write_state(self, state: dict) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_file.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(state, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(self.state_file)

    def check_influx_health(self) -> int:
        response = self.http.get(
            f"{self.influx_url}/health",
            timeout=10,
        )
        self.influx_health_status = response.status_code
        if response.status_code != 200:
            raise RuntimeError(
                f"InfluxDB health check returned HTTP {response.status_code}."
            )
        return response.status_code

    def handle_event(self, payload: dict) -> tuple[int, dict]:
        thing_id = parse_thing_id(payload)
        if thing_id != self.expected_thing_id:
            with self.lock:
                self.write_state(
                    {
                        "result": "IGNORED",
                        "reason": "thing_id_mismatch",
                        "thing_id": thing_id,
                        "event_topic": payload.get("topic"),
                        "event_path": payload.get("path"),
                        "header_keys": sorted(
                            (payload.get("headers") or {}).keys()
                        ),
                        "value_type": type(payload.get("value")).__name__,
                        "received_at_utc": utc_now(),
                    }
                )
            return 204, {"result": "ignored", "reason": "thing_id_mismatch"}

        values = extract_values(payload)
        if values is None:
            return 422, {"result": "rejected", "reason": "unsupported_event_path"}

        temperature, marker = values
        if (
            not isinstance(temperature, (int, float))
            or isinstance(temperature, bool)
            or not isinstance(marker, str)
            or not marker
        ):
            return 422, {
                "result": "ignored",
                "reason": "temperature_or_run_marker_missing",
            }

        if not self.influx_token:
            raise RuntimeError("The scoped InfluxDB token is empty.")

        received_at = utc_now()
        timestamp_ns = time.time_ns()
        line = format_line_protocol(
            thing_id,
            marker,
            float(temperature),
            timestamp_ns,
        )
        response = self.http.post(
            f"{self.influx_url}/api/v2/write",
            params={
                self.influx_org_parameter: self.influx_org,
                "bucket": self.influx_bucket,
                "precision": "ns",
            },
            headers={
                "Authorization": f"Token {self.influx_token}",
                "Content-Type": "text/plain; charset=utf-8",
            },
            data=line.encode("utf-8"),
            timeout=15,
        )
        response.raise_for_status()

        ditto_headers = payload.get("headers") or {}
        state = {
            "result": "WRITTEN",
            "event_topic": payload.get("topic"),
            "event_path": payload.get("path"),
            "thing_id": thing_id,
            "run_marker": marker,
            "temperature": float(temperature),
            "received_at_utc": received_at,
            "ditto_timestamp": (
                ditto_headers.get("timestamp")
                or ditto_headers.get("time")
            ),
            "influx_point_time_ns": timestamp_ns,
            "influx_http_status": response.status_code,
        }
        with self.lock:
            self.write_state(state)
            self.last_accepted_at = utc_now()
        return 204, {"result": "written"}


def make_handler(writer: Writer):
    class Handler(BaseHTTPRequestHandler):
        def _send_json(self, status: int, value: dict) -> None:
            if status == 204:
                self.send_response(204)
                self.end_headers()
                return
            body = json.dumps(value).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/assessment-metadata" and self.client_address[0] in ("127.0.0.1", "::1"):
                endpoint = urlsplit(writer.influx_url)
                with writer.lock:
                    self._send_json(200, {"service": "ditto-influx-telemetry", "host": endpoint.hostname,
                                          "port": endpoint.port or (443 if endpoint.scheme == "https" else 80),
                                          "last_accepted_at": writer.last_accepted_at})
                return
            if self.path == "/health":
                self._send_json(
                    200,
                    {
                        "status": "ready",
                        "expected_thing_id": writer.expected_thing_id,
                    },
                )
                return
            self._send_json(404, {"error": "not_found"})

        def do_POST(self):
            if self.path != "/events":
                self._send_json(404, {"error": "not_found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError("Event payload must be an object.")
                status, response = writer.handle_event(payload)
                self._send_json(status, response)
            except Exception as exc:
                if (
                    isinstance(exc, requests.HTTPError)
                    and exc.response is not None
                ):
                    error_log = (
                        "event_error HttpError "
                        f"influx_http_status={exc.response.status_code}"
                    )
                else:
                    error_log = (
                        f"event_error {type(exc).__name__} "
                        f"detail={str(exc)[:160]}"
                    )
                print(f"{utc_now()} {error_log}", flush=True)
                self._send_json(
                    500,
                    {
                        "error": type(exc).__name__,
                        "detail": str(exc)[:200],
                    },
                )

        def log_message(self, fmt, *args):
            message = fmt % args
            message = message.replace(writer.influx_org, "[ORG]")
            message = message.replace(writer.influx_bucket, "[BUCKET]")
            print(f"{utc_now()} {message}", flush=True)

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--token-stdin", action="store_true")
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    influx_token = ""
    if args.token_stdin:
        influx_token = sys.stdin.readline().strip()
    elif config.get("influx_token_file"):
        influx_token = Path(
            config["influx_token_file"]
        ).read_text(encoding="utf-8").strip()
    writer = Writer(config, influx_token)
    health_status = writer.check_influx_health()
    server = ThreadingHTTPServer(
        (config.get("listen_host", "0.0.0.0"), int(config["listen_port"])),
        make_handler(writer),
    )
    print(
        f"{utc_now()} influx health {health_status}; "
        f"{utc_now()} writer listening on "
        f"{config.get('listen_host', '0.0.0.0')}:{config['listen_port']}",
        flush=True,
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
