# RiskScope

IoMT Vulnerability & Risk Assessment

Run from the project root with the existing Python virtual environment. Install dependencies if needed. There is no frontend build step.

```powershell
.\venv\Scripts\python.exe -m pip install requests packaging
.\venv\Scripts\python.exe -m assessment_web --port 8765
```

Open http://127.0.0.1:8765. The root opens Home. The server listens on IPv4 loopback. To restart, stop the running server with Ctrl+C, then rerun the start command.

## Assessment contexts

- **Start Assessment → Scan system** uses the existing Docker and NVD pipeline. Activate discovery, select a deployment, assess its vulnerabilities, then select a CVE to see relevant scenario evidence. Docker must be on PATH and NVD must be reachable. No Docker or NVD retrieval starts automatically.
- **Scan system → Historical assessment inputs** opens the historical v7 applicability and scenario inputs. Select a CVE and evaluate a scenario with the saved evidence. The UI distinguishes the evidence timestamp from the new evaluation timestamp.
- **Explore the validated laboratory case → Open experiment evidence** compares two recorded experiments on CVE-2018-12546. Scenario links from assessments select the matching experimental input. Offline evaluation computes fresh EBSR results from v9. Evidence links expose curated source fields and artifact provenance. The archived scopes stay separate from live assessments.

Select **Start Assessment** to discover Docker components. Selecting a deployment scans its version. Selecting an affected CVE evaluates the first unambiguous downstream deployment using the discovery and scan snapshot. **Confirm or change the intended route** lists alternatives, including a longer route where the intermediate deployment was discovered. An operator can record an intended connection or configuration review and an optional evidence record ID on the final edge. Generated EBSR inputs are stored under `output/live_scenarios`.

Network aliases and hostnames from allowlisted MQTT/InfluxDB endpoint settings are passive correlation clues, not proof of an application connection. A shared network or matching setting leaves application data flow, CVE-specific capability and receiver processing unresolved. No active connection or exploit test runs. Affected CVE selection generates a deployment-scoped EBSR input automatically; operators do not need to create scenario JSON by hand. UNKNOWN or otherwise unconfirmed CVEs receive a saved component-bounded context rather than a generic dead end. The optional manually curated `scenarios/deployment_scoped.json` workflow remains available separately for compatible evidence.

## Component-bounded assessment

Mosquitto, Eclipse Ditto and InfluxDB can all be assessed without a CVE-specific scenario file. RiskScope preserves the selected deployment and version, reports its entry/intermediate/terminal position in the supported architecture, and discovers only adjacent deployment pairs. The component context keeps four questions separate: applicability, architecture-path evidence, CVE-specific consequences, and whether the numerical EBSR engine could be used. It also records potential consequence categories from the selected CVSS impact vector as advisory only, never as observed target effects.

An UNKNOWN applicability state is never passed into the numerical evaluator. The report states that no feasibility interval or target C/I/A magnitude was calculated and recommends authoritative advisory, version/CPE and configuration evidence. InfluxDB is terminal within the implemented three-component scope; its component-level assessment does not infer Healthcare Monitoring or any other downstream effect. An AFFECTED terminal component may use the frozen evaluator with a `DIRECT` self-transition, while CVE prerequisites, capability, receiver controls and target consequences remain UNKNOWN unless separately supported.

Connection evidence uses five explicit states. `VERIFIED_CONFIGURATION` means the inspected application configuration names the exact peer endpoint and deployment but no collection-window traffic was observed. `OBSERVED_COMMUNICATION` adds successful ordinary-traffic counters; it still does not establish exploitation. `NETWORK_ONLY` means only Docker-network or endpoint-namespace overlap was established. `NOT_CONFIGURED` means a successfully read configuration inventory contains no matching application connection for the exact deployment pair. `UNKNOWN` covers authentication failure, permission denial, incomplete inventory, or an unresolved intermediate destination. Only the two supported states make `B` TRUE. CVE-specific capability (`K`), receiver controls (`Y`) and target C/I/A consequences remain separate.

## Reports

Completed scans and scenario evaluations are saved in `output/web_assessments`. Opening a selected CVE report also saves its applicability and scoped EBSR status. Reopening an identical finding reuses its existing report. HTML opens with the findings, limitations and recommended validation; the technical appendix and JSON retain the evidence trace. Reports defaults to web assessments and the canonical evaluated v9 archive. Enable **Include historical CLI snapshots and replays** to browse earlier inputs and outputs. Nothing is moved or deleted by this filter.

Selections and unsaved results stay available while moving between pages in the same browser tab and server session. Saved reports remain on disk after the server stops.

## Verification

```powershell
.\venv\Scripts\python.exe -m pytest -q
node --test assessment_web/test_navigation.cjs
```

The HTTP integration suite uses mocked Docker and NVD inputs with real historical and experimental evidence. The JavaScript regression checks Home, assessment and report navigation, CVE sorting and filtering, and the round trip from a live CVE to a related experiment and back.

Representative demonstration cases are: Mosquitto `mosquitto-vuln-lab` with CVE-2018-12546; InfluxDB `influxdb-lab` with CVE-2024-30896; and the discovered Eclipse Ditto deployment with one of its returned CVE candidates. The first should retain its existing affected/configuration/UNKNOWN-impact separation and related v9 experiment. The second should show `APPLICABILITY_UNKNOWN`, terminal position, missing prerequisites, read-only next actions, and no numerical result. The Ditto case follows the same evidence rules and does not require a fabricated CVE scenario.

Live Docker and NVD verification requires the user's Docker Desktop environment. If the Docker CLI is unavailable in the agent process, the mocked integration checks do not establish live access or current deployment connectivity.

### Passive evidence collection

Discovery reads Docker member IDs, image identity, start time, aliases and TCP bindings. It compares identities before and after inspection and rechecks the route members and their network/port bindings at evaluation. Refresh Docker discovery and rescan after 15 minutes. Mosquitto inspection reads only the two recognized main config locations. It records listener, authentication and retained-message declarations plus a redacted ACL summary of rule types and scopes. Password files and credential values are never read. Include files, ACL usernames/topic literals and effective per-listener authorization remain outside this inspection. Log inspection counts recognized event signatures in at most 120 recent lines per member. Raw lines and MQTT payloads are discarded.

On a local Docker engine, RiskScope attempts GET requests on the Ditto gateway and InfluxDB ports. The Ditto connection API requires its DevOps Basic credential; an ordinary Things API credential is not interchangeable. Unpublished APIs may be read inside the verified service member using its existing curl executable. The optional read-only credentials are process environment variables: RISKSCOPE_DITTO_USER / RISKSCOPE_DITTO_PASSWORD or RISKSCOPE_INFLUX_READ_TOKEN. Bind credentials to the authorized published port with RISKSCOPE_DITTO_API_PORT or RISKSCOPE_INFLUX_API_PORT. For an unpublished service set the corresponding RISKSCOPE_DITTO_DEPLOYMENT_ID or RISKSCOPE_INFLUX_DEPLOYMENT_ID. Anonymous GET is attempted otherwise. Authentication and permission failures are recorded as HTTP 401 or 403 with a constant inventory status. Never enter a password in a report, evidence reference or scenario file.

Ditto observations record direction, endpoint, connection ID, status, source/target fingerprints, presence of authorization/mapping, and successful consumption/dispatch metrics. Raw topic names, mapping names and credentials are not persisted. The peer must resolve uniquely on the applicable networks or local published port. Only an event inside the inspection window with stable configuration can support observed communication. Earlier activity remains diagnostic. InfluxDB metadata collection reads up to 100 organization and bucket IDs each. The bundled host telemetry writer can expose its storage port and last accepted write time through a loopback-only GET while running. An outbound writer path without matching storage metadata remains `UNKNOWN`; it is not labelled `NOT_CONFIGURED`. The scanner never starts the writer or sends test traffic.
