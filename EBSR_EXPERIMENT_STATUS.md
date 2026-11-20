# IoMT experiment-to-EBSR integration status

The v9 bundle evaluates six saved CVE-2018-12546 scenarios. The archived v8 bundle, v8 reports, original experiment JSON, verification JSON and CSV exports match their pre-audit SHA-256 hashes. The frozen evaluator also matches its v8 hash.

## Verified implementation and evidence

- Automated Docker component and version detection, NVD retrieval, deployment-specific CPE applicability and CVSS reporting are implemented and covered by the offline suite. This audit used the saved applicability and runtime evidence.
- Experiment 1 captured retained delivery after verified publisher ACL revocation on the temporary Mosquitto 1.5.5 broker. The temporary 2.1.2 broker with explicit source checking withheld the marker. A fresh authorized control subscriber received an authorized retained replacement on the same topic.
- Experiment 2 captured the vulnerable marker changing the isolated Ditto Thing and reaching InfluxDB. The annotated CSV contains two matching 42.75 records at 20:10:26.0464382Z and 20:10:26.2222261Z on 18 November 2026. The later verified CSV resolves the original run's pending readback. The control had zero retained-marker records in the verified window and had matching normal and post-control records.
- The saved runs record verified cleanup. Experiment 1 covers direct broker delivery. Experiment 2 covers the captured DF transitions on the named broker deployments and the isolated Thing, connection and writer configuration. V9 separates Experiment 1 actor identities from Experiment 2 and records the applicable endpoints, transition, event and evidence window. The historical manual grade remains in its historical bundle. Baseline assessments retain their own scope.

## Condition audit

| Variable | Evidence and v9 interpretation |
|---|---|
| A | Saved affected boundary plus the captured runtime version. The CVE-carrying 1.5.5 steps are true and the 2.1.2 controls are false. |
| G | Captured authenticated publisher and initial write permission. |
| H | Captured broker configuration, retained-message setup and enforced revocation, or the observed writer prerequisites for the CVE-free step. |
| B | Direct deployment scope or observed DF relationship. Authorized control traffic supports the relationship for both downstream links. |
| K | Broker-level control K remains false because the broker withheld the affected marker under the tested configuration. CVE-free control K is unknown because the affected event never reached that step. |
| Y | The direct control is true for subscriber-side processing and access, supported by the authorized retained replacement. Ditto and InfluxDB control Y are unknown for the withheld event. Their normal and post-control processing was verified. |

A and G stay unknown on the CVE-free Ditto-to-InfluxDB step in both arms because the frozen propositions have no defined interpretation there. The vulnerable interval expresses model feasibility under those unresolved gates. The CSV independently establishes what happened in the captured run.

## Scenario results

| Scenario target | Vulnerable feasibility | Control feasibility | Target integrity, vulnerable / control |
|---|---|---|---|
| Mosquitto | [0.7294117647058823, 0.7294117647058823] | [0, 0] | Unknown / unknown |
| Ditto | [0.7294117647058823, 0.7294117647058823] | [0, 0] | Observed and unquantified / false for the tested event |
| InfluxDB | [0, 0.7294117647058823] | [0, 0] | Observed and unquantified / false for the tested event |

Control Ditto integrity covers the isolated Thing during the retained observation. Control InfluxDB integrity covers the exact marker and Thing in the database readback support window from 20:10:54.5185371Z to 20:11:45.783455Z, end exclusive. Target confidentiality and availability remain unknown. EBSR feasibility is a model interval. Source CVSS and target impact remain separate.

The remaining research limits are event-specific receiver behaviour on a control path that actually receives the affected event, frozen A/G semantics for CVE-free transitions, target impact magnitude, duplicate-row cause and validation of Healthcare Monitoring. Healthcare Monitoring remains architectural context.

The focused suite passed **60 tests** and 5 subtests. The full suite passed **302 tests** and 17 subtests, including the focused tests and all six new regressions. No repository or ancestor AGENTS.md was found. Pytest was installed into the project virtual environment to run the full suite.

## Offline PowerShell commands

Run from the repository root. The comparison runner reads the existing v8 evaluated and replayed reports and verifies both versions offline. A fresh output folder preserves historical reports.

```powershell
$python = '.\venv\Scripts\python.exe'
$run = Join-Path 'output/ebsr_assessments' ('v9-offline-' + (Get-Date -Format 'yyyyMMdd-HHmmssfff'))
New-Item -ItemType Directory -Path $run | Out-Null
$evaluated = Join-Path $run 'evaluated.json'
$replayed = Join-Path $run 'replayed.json'

& $python tools/build_ebsr_experiment_v9.py
& $python tools/run_ebsr_input.py --input scenarios/ebsr_cve_2018_12546_experiment_v9.json --out $evaluated
& $python tools/run_ebsr_input.py --replay $evaluated --out $replayed
& $python tools/run_ebsr_experiment_v9.py --out $run
& $python -m pytest -q
```
