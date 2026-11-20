"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

test("related experiment navigation opens the intended scenario and preserves live selection", async () => {
  const calls = [];
  const scenario = {
    context: "experiment", scenario_id: "EXP2-CORRELATED", cves: ["CVE-2018-12546"],
    target: "Ditto", target_deployment_id: "ditto-test", scope: "Temporary experiment",
    sources: [{deployment_id: "broker-test", version: "1.5.5"}], windows: [],
    reproduction: {"CVE-2018-12546": ["INDEPENDENTLY_REPRODUCED"]},
    attacker: {description: "Recorded actor", capabilities: []},
  };
  const live = {results: {}, assessment: {
    captured_at: "2026-01-01T00:00:00Z", deployment: {product: "Mosquitto", version: "1.5.5", deployment_id: "broker-live"},
    retrieval: {status: "COMPLETE", received: 1, total_results: 1},
    rows: [
      {cve_id: "CVE-2024-10525", status: "UNKNOWN"},
      {cve_id: "CVE-2018-12546", status: "AFFECTED", cvss: {primary: {score: 6.5, severity: "MEDIUM"}}},
    ],
  }};
  const responses = {
    "/api/session": live,
    "/api/reports": {reports: []},
    "/api/coverage?cve=CVE-2018-12546": {
      coverage: "related", compatible: [], errors: [], related: [scenario], missing: [],
    },
    "/api/experiment": {scenarios: [{...scenario, scenario_id: "ANOTHER"}, scenario]},
    "/api/evidence": {runs: [], readback: {window: {}, rows: [], source: {path: "saved.json"}}},
  };
  const elements = new Map();
  const document = {
    querySelector(selector) {
      if (["#cve-table", "#report-table"].includes(selector)
          && !elements.get("#view")?.innerHTML?.includes(`id="${selector.slice(1)}"`)) return null;
      if (!elements.has(selector)) elements.set(selector, {addEventListener() {}, setAttribute() {}});
      return elements.get(selector);
    },
    querySelectorAll() { return []; },
  };
  const runtime = vm.createContext({
    document, crypto, AbortSignal, location: {hash: ""}, window: {addEventListener() {}, setAttribute() {}},
    sessionStorage: {getItem() {}, setItem() {}},
    fetch: async (route, request) => {
      calls.push([route, request.method]);
      assert.ok(Object.hasOwn(responses, route), route);
      return {ok: !responses[route]?.error, status: responses[route]?.error ? 404 : 200, json: async () => responses[route]};
    },
  });
  document.querySelector("#view").innerHTML = fs.readFileSync(path.join(__dirname, "index.html"), "utf8").match(/<div id="view">([\s\S]*?)<\/div><\/main>/)[1];
  const client = fs.readFileSync(path.join(__dirname, "app.js"), "utf8");
  await vm.runInContext(client, runtime);
  const markup = () => document.querySelector("#view").innerHTML;
  assert.match(markup(), /<h1>RiskScope<\/h1>/);
  assert.match(markup(), /Start Assessment/);
  assert.doesNotMatch(markup(), /Discover deployments<\/button>/);
  await vm.runInContext('location.hash = "#reports"; navigate()', runtime);
  assert.match(markup(), /Saved reports/);
  await vm.runInContext('location.hash = "#assessments"; navigate()', runtime);
  assert.match(markup(), /Discovery not started/);
  await vm.runInContext(`
    state.steps.live = "vulnerabilities";
    render();
    state.filters.live.cvsort = "score";
    filteredTable(state.server.assessment.rows);
  `, runtime);
  const table = () => document.querySelector("#cve-table").innerHTML;
  assert.ok(table().indexOf("CVE-2018-12546") < table().indexOf("CVE-2024-10525"));
  vm.runInContext('state.filters.live.applicability = "UNKNOWN"; filteredTable(state.server.assessment.rows)', runtime);
  assert.match(table(), /CVE-2024-10525/);
  assert.doesNotMatch(table(), /CVE-2018-12546/);
  await vm.runInContext(`
    state.selected.liveDeployment = "broker-live";
    state.selected.liveCve = "CVE-2018-12546";
    state.steps.live = "scenarios";
    loadCoverage(state.selected.liveCve);
  `, runtime);
  assert.match(markup(), /#experiment\/EXP2-CORRELATED\/CVE-2018-12546/);
  assert.match(markup(), /View Experimental Evidence/);
  assert.match(markup(), /Live deployment risk assessment not yet available/);
  assert.match(markup(), /Continue to report/);
  assert.match(markup(), /NOT_ASSESSED/);
  await vm.runInContext('location.hash = "#experiment/EXP2-CORRELATED/CVE-2018-12546/evidence"; navigate()', runtime);
  assert.match(markup(), /Saved experimental evidence/);
  assert.match(markup(), /Recorded experimental configuration/);
  await vm.runInContext('location.hash = "#live"; navigate()', runtime);
  assert.equal(vm.runInContext("state.selected.liveDeployment", runtime), "broker-live");
  assert.equal(vm.runInContext("state.selected.liveCve", runtime), "CVE-2018-12546");
  assert.match(markup(), /View Experimental Evidence/);
  for (const invalid of [{error: "This assessment endpoint does not exist."}, {}]) {
    responses["/api/reports"] = invalid;
    await vm.runInContext('location.hash = "#reports"; navigate()', runtime);
    const output = document.querySelector("#report-table").innerHTML;
    assert.match(output, /Retry/);
    assert.doesNotMatch(output, /Loading saved reports/);
  }
  responses["/api/reports"] = {reports: []};
  await vm.runInContext('navigate()', runtime);
  assert.match(document.querySelector("#report-table").innerHTML, /No reports saved/);
  const guidance = vm.runInContext(`guidancePanel({
    verified: ["Mosquitto to Eclipse Ditto: configuration verified."],
    unknown: ["CVE-specific transition capability remains unknown."],
    refresh_available: true,
    next_action: {kind: "CONTROLLED_VALIDATION", label: "Review controlled CVE validation", detail: "Use the exact deployment."},
    layers: [
      {key: "configuration", label: "Configuration", status: "VERIFIED"},
      {key: "communication", label: "Observed communication", status: "UNKNOWN"},
      {key: "cve", label: "CVE-specific behaviour", status: "U"},
      {key: "impact", label: "Downstream impact", status: "U"}
    ],
    receiver: {label: "Receiver processing and controls", status: "U"}
  })`, runtime);
  assert.match(guidance, /Refresh read-only evidence/);
  assert.match(guidance, /Review bounded validation/);
  assert.match(guidance, /Receiver processing and controls/);
  assert.match(guidance, /Configuration<\/span><strong>Verified/);
  assert.match(guidance, /CVE-specific transition capability remains unknown/);
  const bounded = vm.runInContext(`boundedAssessmentPanel({reason: "Applicability UNKNOWN.", bounded_context: {
    deployment: {product: "InfluxDB", version: "2.7.11", deployment_id: "influxdb-lab"},
    architecture_position: {label: "Terminal supported component", terminal_component: true},
    assessment_states: {
      applicability: {status: "UNKNOWN", classification: "APPLICABILITY_UNKNOWN"},
      architecture_path: {status: "NO_VERIFIED_ARCHITECTURE_PATH"},
      cve_specific_consequences: {status: "INSUFFICIENT_EVIDENCE"},
      engine: {status: "AVAILABLE_NOT_EXERCISED"}
    },
    relationships: [{source_product: "Eclipse Ditto", target_product: "InfluxDB",
      verification: "UNKNOWN", verification_reason: "Application relationship unresolved."}],
    known_facts: ["InfluxDB is terminal in the supported architecture."],
    missing_evidence: ["CVE applicability remains UNKNOWN."],
    potential_consequence_categories: {categories: [], reason: "No observed effects."},
    recommended_actions: [{label: "Resolve applicability", detail: "Review the advisory."}],
    numerical_assessment: {status: "NOT_CALCULATED", reason: "No numerical interval is supported."},
    provenance: {discovery_captured_at: "2026-01-01T00:00:00Z"}
  }})`, runtime);
  assert.match(bounded, /Component-bounded assessment/);
  assert.match(bounded, /Applicability: APPLICABILITY UNKNOWN/);
  assert.match(bounded, /Terminal supported component/);
  assert.match(bounded, /NO_VERIFIED_ARCHITECTURE_PATH/);
  assert.match(bounded, /Numerical EBSR status: <strong>NOT_CALCULATED/);
  assert.doesNotMatch(bounded, /attack probability/i);
  const boundedCoverage = vm.runInContext(`state.server.assessment = {
      deployment: {product: "InfluxDB", version: "2.7.11", deployment_id: "influxdb-lab"},
      retrieval: {status: "COMPLETE"}, captured_at: "2026-01-01T00:00:00Z", rows: []
    };
    state.server.discovery = {supported: [
      {product: "InfluxDB", version: "2.7.11", deployment_id: "influxdb-lab"}
    ]};
    state.selected.routeNode = "InfluxDB";
    state.coverage = {
      key: coverageKey("CVE-2024-30896"), coverage: "none", compatible: [], related: [],
      missing: ["CVE applicability remains UNKNOWN."], errors: []
    };
    state.analysis = {
      key: coverageKey("CVE-2024-30896"), status: "NOT_ASSESSED",
      assessment_state: "APPLICABILITY_UNKNOWN", reason: "Applicability UNKNOWN.",
      guidance: {verified: [], unknown: ["Applicability remains UNKNOWN."], next_action: {
        label: "Resolve applicability", detail: "Review the advisory."
      }},
      bounded_context: {
        deployment: {product: "InfluxDB", version: "2.7.11", deployment_id: "influxdb-lab"},
        architecture_position: {label: "Terminal supported component", terminal_component: true},
        assessment_states: {
          applicability: {status: "UNKNOWN", classification: "APPLICABILITY_UNKNOWN"},
          architecture_path: {status: "NO_VERIFIED_ARCHITECTURE_PATH"},
          cve_specific_consequences: {status: "INSUFFICIENT_EVIDENCE"},
          engine: {status: "AVAILABLE_NOT_EXERCISED"}
        },
        relationships: [], known_facts: ["InfluxDB is terminal in the supported architecture."],
        missing_evidence: ["CVE applicability remains UNKNOWN."],
        potential_consequence_categories: {categories: [], reason: "No observed effects."},
        recommended_actions: [{label: "Resolve applicability", detail: "Review the advisory."}],
        numerical_assessment: {status: "NOT_CALCULATED", reason: "No numerical interval is supported."},
        provenance: {discovery_captured_at: "2026-01-01T00:00:00Z"}
      }
    };
    liveCoverage("CVE-2024-30896")`, runtime);
  assert.match(boundedCoverage, /COMPONENT-BOUNDED ASSESSMENT — INCOMPLETE EVIDENCE/);
  assert.match(boundedCoverage, /No numerical EBSR profile was calculated/);
  assert.doesNotMatch(boundedCoverage, /No scenario was found for this CVE and product/);
  assert.doesNotMatch(boundedCoverage, /requires a scenario/);
  assert.doesNotMatch(boundedCoverage, />NOT_ASSESSED</);
  const controlledEvidence = vm.runInContext(`state.experimentEvidenceError = "";
    state.evidence = {
      runs: [
        {number: 1, cve: "CVE-2018-12546", window: {start: "t1", stop: "t2"}, source: {path: "run1.json", sha256: "hash1"},
          arms: {
            vulnerable: {version: "1.5.5", deployment: "vuln-broker", source_check: null, cleanup: "VERIFIED",
              counts: {stale_original_marker: 1}},
            control: {version: "2.1.2", deployment: "control-broker", source_check: "true", cleanup: "VERIFIED",
              counts: {stale_original_marker: 0}}
          }},
        {number: 2, cve: "CVE-2018-12546", window: {start: "t3", stop: "t4"}, source: {path: "run2.json", sha256: "hash2"},
          arms: {
            vulnerable: {version: "1.5.5", deployment: "vuln-flow", cleanup: "VERIFIED", initial_temperature: 37,
              retained_temperature: 42.75, thing_id: "thing:vulnerable", marker: "marker-v", records: 2,
              thing_changed: true, normal_verified: true, post_control_verified: true},
            control: {version: "2.1.2", deployment: "control-flow", cleanup: "VERIFIED", initial_temperature: 37,
              retained_temperature: 37, thing_id: "thing:control", marker: "marker-c", records: 0,
              thing_changed: false, normal_verified: true, post_control_verified: true}
          }}
      ],
      readback: {status: "CONFIRMED", verified_at_utc: "t5", source: {path: "readback.json", sha256: "hash3"},
        rows: [{time: "t6", value: 42.75, run_marker: "marker-v", thing_id: "thing:vulnerable"}]}
    };
    relatedControlledEvidence("CVE-2018-12546", {scenario_id: "EXP2-CORRELATED"})`, runtime);
  assert.match(controlledEvidence, /Related Controlled Experimental Evidence/);
  assert.match(controlledEvidence, /Mosquitto 1\.5\.5/);
  assert.match(controlledEvidence, /Mosquitto 2\.1\.2/);
  assert.match(controlledEvidence, /check_retain_source=true/);
  assert.match(controlledEvidence, /changed from 37 to 42\.75/);
  assert.match(controlledEvidence, /confirmed 2 retained-marker rows/);
  assert.match(controlledEvidence, /no corresponding Thing change/i);
  assert.match(controlledEvidence, /no retained-marker rows/i);
  assert.match(controlledEvidence, /Cleanup<\/dt><dd>Verified for both arms/);
  assert.match(controlledEvidence, /Historical results from isolated temporary deployments/);
  assert.match(controlledEvidence, /not evidence of exploitation in the currently selected live deployment/i);
  assert.match(controlledEvidence, /#experiment\/EXP2-CORRELATED\/CVE-2018-12546\/evidence/);
  assert.match(controlledEvidence, /Duplicate-row causation was not established/);
  assert.match(controlledEvidence, /numerical magnitude of security impact was not measured/);
  assert.match(controlledEvidence, /readback\.json/);
  assert.ok(calls.some(([route]) => route === "/api/evidence"));
  assert.ok(calls.every(([, method]) => method === undefined));
});
