# Isolated Ditto → InfluxDB telemetry writer

This lab-only link consumes Thing events emitted by Ditto over an
`http-push` connection and writes matching numeric telemetry into a dedicated
InfluxDB bucket.

The writer:

- listens on `0.0.0.0:8095`;
- accepts only the configured isolated Thing ID;
- requires numeric `temperature` and string `runMarker` attributes;
- writes one InfluxDB point only after Ditto emits the event;
- receives the scoped InfluxDB token through standard input when started by
  the validation or start helper;
- records a redacted local state file with event and write timestamps.

The Ditto connection is defined by
[`connection.template.json`](connection.template.json). A validation run
creates a versioned Ditto connection, test policy, test Thing and dedicated
InfluxDB bucket, then closes the connection and stops the writer.

## Validate and create a new isolated link

From the repository root:

```powershell
.\venv\Scripts\python.exe .\scripts\run_ditto_influx_validation.py
```

The command prompts locally for:

1. the ordinary Ditto `ditto` password, using hidden input;
2. the local InfluxDB administrator token, using hidden input.

Credentials are not printed or written into evidence. The generated runtime
configuration is stored below:

```text
%LOCALAPPDATA%\IoMT-Lab-Backups\DittoInfluxTelemetry\<run-id>\
```

Resume validation against the existing bucket:

```powershell
.\venv\Scripts\python.exe .\scripts\resume_ditto_influx_validation.py `
  --bucket iomt-ditto-influx-test-cd1c965d2a `
  --org IoMT-Lab `
  --cleanup-config <path-to-interrupted-link-config.json>
```

This path prompts for the ordinary Ditto password and the write-only token,
passes the token to the writer through standard input, and leaves InfluxDB
readback pending for manual Data Explorer confirmation.

The validation closes the Ditto connection and stops the writer after the
test. The dedicated bucket and test artifacts remain available for inspection.

## Start a validated link

```powershell
.\scripts\start_ditto_influx_telemetry.ps1
```

This starts the writer using the latest private runtime configuration and opens
its Ditto HTTP-push connection. It requires the local Ditto DevOps credential
in the gateway container metadata.

## Stop a validated link

```powershell
.\scripts\stop_ditto_influx_telemetry.ps1
```

This closes the Ditto connection before stopping the writer process.

## Reproduction boundary

A successful run establishes that:

1. Ditto emitted an event for the isolated Thing;
2. the HTTP-push writer received the event;
3. the writer wrote the numeric temperature and run marker to InfluxDB;
4. the InfluxDB row matches the Thing ID and API-read Thing value.

It does not establish vulnerability exploitation, attack feasibility or adverse
confidentiality, integrity or availability impact.
