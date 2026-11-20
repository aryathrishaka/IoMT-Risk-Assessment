# IoMT assessment workflow and technical results

## Saved baseline comparison

Counts describe the candidates saved in each artifact. The affected column includes both the primary CVSS group and the separate other-scale group. These are distinct snapshots with uneven metadata. File modification times below are UTC workspace metadata. The two EBSR report dates come from their embedded `generated_at` fields and date report generation.

| Saved component and version | Deployment in artifact | Retrieval | Candidates | Affected | Not affected | Unknown | Date and source |
|---|---|---|---:|---:|---:|---:|---|
| Mosquitto 1.5.5 | Unrecorded | Unrecorded | 35 | 10 | 23 | 2 | 2026-10-11 13:30:13Z, file mtime. [Legacy export](mosquitto_1.5.5_baseline_results.json) |
| Mosquitto 1.5.5 | `mosquitto-vuln-lab` | COMPLETE, 37 of 37 | 37 | 10 | 23 | 4 | 2026-11-10 14:08:55.938846Z, report generation. [Deployment assessment](output/ebsr_assessments/ebsr-assessment-20261110T140855977011Z-v1.0.json) |
| Mosquitto 2.1.2 | Unrecorded | Unrecorded | 35 | 0 | 33 | 2 | 2026-10-11 13:33:43Z, file mtime. [Legacy export](mosquitto_2.1.2_baseline_results.json) |
| Eclipse Ditto 3.9.7 | Unrecorded | Unrecorded | 11 | 0 | 7 | 4 | 2026-10-11 13:24:18Z, file mtime. [Legacy export](ditto_baseline_results.json) |
| Eclipse Ditto 3.9.7 | `docker` | COMPLETE, 11 of 11 | 11 | 0 | 7 | 4 | 2026-11-17 15:10:40.036892Z, report generation. [Deployment assessment](output/ebsr_assessments/ebsr-assessment-20261117T151040058022Z-v1.0.json) |
| Eclipse Ditto 3.9.7 | `docker` | COMPLETE, 11 of 11 | 11 | 0 | 7 | 4 | 2026-11-18 18:37:46Z, file mtime. Embedded retrieval time unrecorded. [Deployment-aware baseline export](output/ditto-baseline-20261119-000737.json) |
| InfluxDB 2.7.11 | Unrecorded | Unrecorded | 8 | 0 | 7 | 1 | 2026-10-11 13:31:45Z, file mtime. [Legacy export](influxdb_2.7.11_baseline_results.json) |
| InfluxDB 2.7.11 | `influxdb-lab` | COMPLETE, 9 of 9 | 9 | 0 | 7 | 2 | 2026-11-17 15:27:31Z, recovered file mtime. Embedded retrieval time unrecorded. [Recovered baseline export](output/influxdb-baseline-recovered-20261119-000730.json) |

[The legacy aggregate](all_baseline_results.json) duplicates the four legacy component exports, and [the generic baseline result](baseline_results.json) is byte-identical to the legacy Mosquitto 2.1.2 export. The legacy records support component/version counts only. A deployment-aware 2.1.2 baseline with an independently recorded retrieval status and date was absent from the inspected artifacts. V9's control rows describe temporary experimental deployments. Matching counts across the Ditto records do not establish a common retrieval time. The Mosquitto 1.5.5 and InfluxDB candidate totals differ across their respective saved records. Zero confirmed affected candidates is a result within the saved candidate set.

## Reproduce from PowerShell

Run from the project root with Python 3.14 or the project virtual environment. The standalone offline tool was verified with site packages disabled. It needs the saved JSON inputs and a writable output directory. Docker, credentials and network access are unnecessary for this route.

```powershell
$python = '.\venv\Scripts\python.exe'
$run = Join-Path 'output/ebsr_assessments' ('workflow-' + (Get-Date -Format 'yyyyMMdd-HHmmssfff'))
New-Item -ItemType Directory -Path $run | Out-Null

$historical = Join-Path $run 'historical-v7.json'
$evaluated = Join-Path $run 'experiment-v9.json'
$replayed = Join-Path $run 'experiment-v9-replay.json'
& $python -S tools/run_ebsr_input.py --input 'scenarios/ebsr_mosquitto_12546_12550_12551_v7.json' --out $historical
& $python -S tools/run_ebsr_input.py --input 'scenarios/ebsr_cve_2018_12546_experiment_v9.json' --out $evaluated
& $python -S tools/run_ebsr_input.py --replay $evaluated --out $replayed

& $python -c "import json,sys; a,b=(json.load(open(p,encoding='utf8')) for p in sys.argv[1:]); assert all(a[k]==b[k] for k in ('scenario_results','propositions','component_profiles')); print('Replay matched')" $evaluated $replayed
```

V7 prints its historical assessment version and evaluates seven scenarios with manual or untested source grades. V9 prints its experimental assessment version and evaluates six scenarios with run-specific evidence and source/downstream scope. Replay recomputes the saved propositions, scenarios and profiles. Report generation and replay metadata differ between those outputs.

A legacy CVSS export can be read with `Get-Content -Raw .\mosquitto_2.1.2_baseline_results.json | ConvertFrom-Json`. The two deployment assessment reports in the table are EBSR report objects. Replaying them with `tools/run_ebsr_input.py --replay <report> --out <new-file>` prints `NOT_ASSESSED` for scenario risk because those reports lack a complete evidence-backed scenario. With the project dependencies installed, `main.py --ebsr-replay` is an equivalent replay entry point for saved EBSR reports.

For a future current-deployment assessment, the live entry points require a reachable Docker engine with the target deployments running, NVD network access, and Python packages `requests` and `packaging`. Their argument parsing and assessment paths were exercised with offline mocks. The following commands start live discovery and NVD retrieval when run normally.

```powershell
& $python baseline.py --out (Join-Path $run 'current-baseline.json')
& $python main.py --ebsr-out (Join-Path $run 'current-deployment-ebsr.json')
```

`baseline.py` writes a CVSS baseline JSON array with a deployment-specific retrieval status, UTC recording time and applicability bins. `main.py` prompts for a discovered deployment and can prompt for an applicable CVE. Its versioned report records discovery, candidate applicability and scenario coverage. The live `--ebsr-scenarios` option accepts scenario inputs for the live workflow. Saved experimental bundles are rejected before discovery, including when a baseline shares the product/version or the InfluxDB endpoint ID. Use the offline commands for those bundles.

## Final technical results

- **Automated discovery and applicability.** Docker evidence provides deployment identities and version provenance. The NVD retrieval layer distinguishes complete, partial, failed and malformed responses. CPE evaluation records affected, not affected and unknown decisions. CVSS v3.x drives baseline ranking, with other CVSS scales reported separately.
- **Paired Experiment 1.** After verified publisher ACL revocation, the temporary Mosquitto 1.5.5 broker delivered the retained marker. The temporary 2.1.2 broker with explicit source checking withheld it and delivered an authorized retained replacement. [Saved run](output/evidence_runs/cve-2018-12546-retained-acl-20261118T195233320714Z.json)
- **Paired Experiment 2.** The vulnerable retained marker changed an isolated Ditto Thing and reached InfluxDB. CSV readback confirmed two matching `42.75` records at distinct timestamps. The control had no retained-marker row during the verified window. Normal and authorized post-control records were present. [Saved run](output/evidence_runs/cve-2018-12546-downstream-20261118T200923198752Z.json) · [Readback verification](output/evidence_runs/cve-2018-12546-downstream-20261118T200923198752Z-readback.json)
- **V9 EBSR profiles.** Vulnerable feasibility is `[0.729412, 0.729412]` for Mosquitto and Ditto, and `[0, 0.729412]` for InfluxDB. All three controls are `[0, 0]`. Vulnerable Ditto and InfluxDB target integrity consequences are observed and unquantified. Control Ditto and InfluxDB integrity consequences were absent within the tested event windows. The unresolved CVE-free A/G gates explain the zero lower bound for vulnerable InfluxDB despite confirmed storage. The equations retain separate source CVSS and target impact. [V9 audit and scope](EBSR_EXPERIMENT_STATUS.md)
- **Provenance and cleanup.** The saved runs record verified cleanup. V9 retains the experimental deployment identities, event markers and observation windows. V7 retains historical manual observations. The working-tree verification checked 95 existing artifact and evaluator hashes before and after the workflow. The guarded live entry points keep current baseline evidence outside the saved experiment bundle.
- **Remaining technical work.** A future same-window baseline capture would close the legacy metadata gaps and support a contemporaneous comparison. The duplicate-row cause, quantitative target impact, control receiver handling of an affected event, and interpretation of A/G for CVE-free steps remain open. Healthcare Monitoring is architectural context and remains outside the experimentally validated path.

The complete offline suite passed **304 tests and 20 subtests** using `& $python -m pytest -q`. The full count includes the live-entry regression tests and baseline timestamp check. V7, v9 and the saved baseline report replays were also exercised through their supported PowerShell entry points. No live experiments or fresh NVD retrieval were performed.
