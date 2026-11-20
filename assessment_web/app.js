"use strict";

const view = document.querySelector("#view");
const homeTemplate = view.innerHTML;
const notice = document.querySelector("#notice");
const titles = {architecture: "Architecture Risk", home: "Home", live: "Assessments", historical: "Assessments", experiment: "Experiments", reports: "Reports"};
const labels = {T: "Established", F: "Contradicted", U: "Unknown", X: "Conflicting evidence"};
const products = {mosquitto: "Mosquitto", ditto: "Eclipse Ditto", influxdb: "InfluxDB"};
const connectionLabels = {
  VERIFIED_CONFIGURATION: "Configuration verified",
  OBSERVED_COMMUNICATION: "Communication observed",
  NETWORK_ONLY: "Shared network only",
  NOT_CONFIGURED: "No matching configuration",
  UNKNOWN: "Unknown"
};
const escape = value => String(value ?? "—").replace(/[&<>"']/g, char => (
  {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[char]
));
const readable = value => String(value ?? "Unrecorded").replaceAll("_", " ");
const safeUrl = url => /^https?:\/\//i.test(url);
const status = (value, tone = "") => `<span class="status ${tone}">${escape(readable(value))}</span>`;
const button = (text, action, options = "") => `<button type="button" class="button ${options.includes("primary") ? "primary" : ""}" data-action="${action}" ${options.includes("disabled") ? "disabled" : ""}>${text}</button>`;
const facts = entries => `<dl class="fact-list">${entries.map(([term, value]) => `<dt>${escape(term)}</dt><dd>${escape(value)}</dd>`).join("")}</dl>`;
const empty = (heading, body) => `<div class="empty"><strong>${escape(heading)}</strong><p>${escape(body)}</p></div>`;
const bounds = interval => interval ? `[${interval.map(value => Number(value.toFixed(6))).join(", ")}]` : "—";
const list = items => items?.length ? `<ul>${items.map(item => `<li>${escape(item)}</li>`).join("")}</ul>` : "";
const windows = items => items?.length ? items.map(w => `${w.start} to ${w.stop_exclusive || w.stop}${w.stop_exclusive ? " (exclusive)" : ""}`).join(" · ") : "See historical evidence sources";
const state = {context: "home", server: {results: {}}, catalogs: {}, selected: {}, reports: {},
  filters: {}, steps: {live: "deployments", historical: "vulnerabilities"}, evidence: null, busy: false};
const sessionId = sessionStorage.getItem("iomt-session") || crypto.randomUUID().replaceAll("-", "");
sessionStorage.setItem("iomt-session", sessionId);

async function api(path, payload) {
  const options = {headers: {"X-Assessment-Session": sessionId}};
  if (path === "/api/reports") options.signal = AbortSignal.timeout(30000);
  if (payload !== undefined) {
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(payload);
  }
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(`HTTP ${response.status}: ${data.error || "The local request failed."}`);
  return data;
}

function message(text, isError = false) {
  notice.hidden = !text;
  notice.className = isError ? "error" : "";
  notice.textContent = text;
}

function architecture(path, observations) {
  const graph = state.server.architecture || {};
  const transitions = path?.transitions || [];
  const active = new Set(transitions.flatMap(step => [products[step.source_product], products[step.target_product]]));
  const nodes = Object.keys(graph).filter(name => Object.values(products).includes(name));
  const diagram = names => `<div class="route" role="img" aria-label="${escape(names.join(" to "))}">
    ${names.map((name, index) => `${index ? '<span class="flow" aria-hidden="true">→</span>' : ""}
      <span class="node ${active.has(name) ? "highlight" : ""}">${escape(name)}</span>`).join("")}</div>`;
  return `${diagram(nodes)}
    <p>${path ? "Highlighted nodes participate in the evaluated route. Normal flow and CVE effects apply only to the recorded scope." : "Configured relationships between the assessed components. Observed flow requires deployment-scoped evidence."}</p>
    ${path ? transitions.map(step => `<p class="provenance"><strong>${escape(step.transition_type)}</strong> · ${escape(step.source)} to ${escape(step.target)}</p>`).join("") : ""}
    ${(observations || []).flatMap(item => item.downstream_targets).map(item =>
      `<div class="sub-card"><strong>${escape(item.target_component)}</strong><br>
      Normal flow ${status(item.normal_path_testing, "good")} · CVE-specific ${status(item.cve_specific_testing)}
      ${item.observation_window_utc ? `<p class="provenance">${escape(windows([item.observation_window_utc]))}</p>` : ""}
      </div>`).join("")}
    <details><summary>Architecture scope</summary>${diagram(Object.keys(graph))}
    <p>The laboratory publisher represents the IoMT device. Healthcare Monitoring is downstream context outside the implemented assessment and experimental validation scope.</p></details>`;
}

function exportPanel() {
  const exported = state.reports[state.context];
  return `<section class="card"><div class="section-head"><div><h2>Report export</h2><p>Download the readable assessment or its structured evidence.</p></div>
      ${exported ? "" : button("Prepare report", "save", state.busy ? "disabled" : "")}</div>
      ${exported ? `<div class="report-links"><span>${escape(exported.saved_at_utc)}</span>
      <a class="button" href="/reports/${escape(exported.report_id)}.html">Download readable report</a>
      <a class="button" href="/reports/${escape(exported.report_id)}.json">Download JSON</a></div>` : ""}</section>`;
}

function deploymentsPanel() {
  const discovery = state.server.discovery;
  const running = state.server.job?.state === "running" || state.busy;
  const rows = discovery?.supported || [];
  const selected = state.selected.liveDeployment;
  const absent = ["Mosquitto","Eclipse Ditto","InfluxDB"].filter(product => !rows.some(row=>row.product === product));
  return `<section class="card" id="deployments"><div class="section-head"><div><h2>Deployments</h2><p>Assess one detected product and version at a time.</p></div>
      ${discovery?.status === "COMPLETE" ? status("Discovery complete", "good") : ""}</div>
      ${state.server.job?.state === "running" ? `<div class="message"><span class="progress"></span>${escape(state.server.job.message)}</div>` : ""}
      ${state.server.job?.state === "error" ? `<div class="message error">${escape(state.server.job.message)}</div>` : ""}
      ${discovery && discovery.status !== "COMPLETE" ? `<div class="message error">${escape(readable(discovery.status))}. Check that the Docker engine is available and retry discovery.</div>` : ""}
      ${discovery ? `<p class="provenance">Discovery captured ${escape(discovery.captured_at)} UTC</p>` : ""}
      ${rows.length ? `<div class="table-wrap"><table><thead><tr><th>Product</th><th>Version</th><th>Deployment ID</th><th>Runtime / discovery</th><th>Version evidence</th><th>Selection</th></tr></thead><tbody>
        ${rows.map(row => `<tr class="${row.deployment_id === selected ? "selected" : ""}"><td><strong>${escape(row.product)}</strong></td><td>${escape(row.version)}</td><td class="mono">${escape(row.deployment_id)}</td><td>${escape(row.runtime)}<br>${status(row.status)}</td><td>${escape(readable(row.version_source))}</td><td>
        <button class="button" data-action="deployment" data-value="${escape(row.deployment_id)}" ${running || !row.assessable ? "disabled" : ""}>${row.deployment_id === selected ? "Selected" : row.assessable ? "Select" : "Unavailable"}</button></td></tr>`).join("")}
        </tbody></table></div>` : !discovery ? empty("Discovery not started", "Discover deployments to list running products, versions and deployment identities.")
          : discovery.status === "COMPLETE" ? empty("No supported deployments found", "Check that the target containers are running, then discover again.") : ""}
      ${discovery?.status === "COMPLETE" && absent.length ? `<p class="provenance">Not discovered: ${escape(absent.join(", "))}.</p>` : ""}
      ${discovery?.other?.length ? `<details><summary>Unsupported or unclassified deployments (${discovery.other.length})</summary>
      <div class="table-wrap"><table><thead><tr><th>Product</th><th>Deployment</th><th>Runtime</th><th>Discovery status</th></tr></thead><tbody>
      ${discovery.other.map(r => `<tr><td>${escape(r.product)}</td><td class="mono">${escape(r.deployment_id)}</td><td>${escape(r.runtime)}</td><td>${status(r.status)}</td></tr>`).join("")}</tbody></table></div></details>` : ""}</section>`;
}

function vulnerabilityPanel(rows, assessment) {
  const context = state.context;
  const filters = state.filters[context] ||= {query: "", applicability: "", severity: "", cvsort: "applicability"};
  const severities = [...new Set(rows.map(row => row.cvss?.primary?.severity).filter(Boolean))].sort();
  const selection = (key, values) => `<select id="${key}"><option value="">All</option>${values.map(v => `<option value="${escape(v)}" ${filters[key] === v ? "selected" : ""}>${escape(readable(v))}</option>`).join("")}</select>`;
  const counts = ["AFFECTED", "NOT_AFFECTED", "UNKNOWN"].map(s => [readable(s), rows.filter(r => r.status === s).length]);
  const retrieval = assessment?.retrieval;
  return `<section class="card" id="vulnerabilities"><div class="section-head"><div><h2>Vulnerability assessment</h2>
    <p>${assessment ? `${escape(assessment.deployment.product)} ${escape(assessment.deployment.version)} · ${escape(assessment.deployment.deployment_id)}` : "Saved historical applicability from the v7 evidence bundle."}</p></div>
    ${retrieval ? status(retrieval.status, retrieval.status === "COMPLETE" ? "good" : "warn") : status("Saved snapshot")}</div>
    ${retrieval ? `<p class="provenance">Captured ${escape(assessment.captured_at)} UTC · NVD received ${escape(retrieval.received)} of ${escape(retrieval.total_results ?? "unknown")}</p>`
    : `<p class="provenance">Historical snapshot generated ${escape(state.catalogs.historical?.historical_snapshot_at)}</p>`}
    ${retrieval && retrieval.status !== "COMPLETE" ? `<div class="message warning">${retrieval.status === "PARTIAL" ? "Retrieval was incomplete. Results cover only the received candidates." : "NVD did not return a usable result. Retry the live assessment when NVD is available."}</div>` : ""}
    <div class="facts">${[["Classified candidates", rows.length], ...counts].map(([label,value]) => `<div class="metric"><strong>${value}</strong><small>${escape(label)}</small></div>`).join("")}</div>
    ${counts[0][1] === 0 && rows.length ? '<p>Zero confirmed affected candidates applies to this retrieved set only. Unknown candidates still need evidence.</p>' : ""}
    ${rows.length ? `<div class="controls"><label>Search CVEs<input id="query" type="search" placeholder="CVE ID or reason" value="${escape(filters.query)}"></label>
    <label>Applicability${selection("applicability", ["AFFECTED", "UNKNOWN", "NOT_AFFECTED"])}</label>
    <label>Severity${selection("severity", severities)}</label>
    <label>Sort by<select id="cvsort">${[["", "Assessment order"], ["cve", "CVE ID"], ["score", "CVSS score (highest first)"], ["applicability", "Applicability"]]
      .map(([key, label]) => `<option value="${key}" ${filters.cvsort === key ? "selected" : ""}>${label}</option>`).join("")}</select></label></div><div id="cve-table"></div>`
    : empty("No candidates to display", "A zero affected count describes the available candidate set only.")}
    </section>`;
}

function filteredTable(rows) {
  const table = document.querySelector("#cve-table");
  if (!table) return;
  const f = state.filters[state.context];
  const query = f.query.trim().toLowerCase();
  const selected = state.selected[state.context + "Cve"];
  const filtered = rows.filter(row => (!f.applicability || row.status === f.applicability)
    && (!f.severity || row.cvss?.primary?.severity === f.severity)
    && (!query || [row.cve_id, row.reason, row.description].some(x => String(x || "").toLowerCase().includes(query))));
  const order = {
    cve: (a, b) => a.cve_id.localeCompare(b.cve_id),
    score: (a, b) => (b.cvss?.primary?.score ?? -1) - (a.cvss?.primary?.score ?? -1),
    applicability: (a, b) => ["AFFECTED","UNKNOWN","NOT_AFFECTED"].indexOf(a.status) - ["AFFECTED","UNKNOWN","NOT_AFFECTED"].indexOf(b.status),
  };
  if (order[f.cvsort]) filtered.sort(order[f.cvsort]);
  table.innerHTML = filtered.length ? `<div class="table-wrap"><table><thead><tr><th>CVE</th><th>Applicability</th><th>Severity</th><th>CVSS version / score</th><th>Applicability reason</th></tr></thead><tbody>
    ${filtered.map(row => {
      const metric = row.cvss?.primary;
      return `<tr class="${selected === row.cve_id ? "selected" : ""}"><td><button class="link-button" data-action="cve" data-value="${escape(row.cve_id)}">${escape(row.cve_id)}</button></td>
        <td>${status(row.status, row.status === "AFFECTED" ? "bad" : row.status === "UNKNOWN" ? "warn" : "")}</td>
        <td>${escape(metric?.severity)}</td><td>${escape(metric?.version)} / ${escape(metric?.score)}</td><td class="reason-cell">${escape(row.reason)}</td></tr>`;
    }).join("")}</tbody></table></div>` : empty("No matching CVEs", "Change or clear the search and filters.");
}

function details(row) {
  const metric = row.cvss?.primary;
  const alternatives = row.cvss?.other || [];
  const metricFacts = m => facts([["Version / score", `${m.version} / ${m.score}`], ["Severity", m.severity], ["Vector", m.vector], ["Source", m.source], ["Source type", m.source_type]]);
  return `<section class="card" id="cve-details"><div class="section-head"><h2>${escape(row.cve_id)}</h2>${status(row.status)}</div>
    <h3>Summary</h3><p>${escape(row.description || "No description was recorded.")}</p>
    <h3>CVSS and applicability</h3><p>${escape(row.reason)}</p>
    ${metric ? facts([["Severity", metric.severity], ["CVSS score", `${metric.score} (v${metric.version})`]]) : "<p>No primary CVSS score recorded.</p>"}
    <details><summary>Technical CVSS metrics and sources</summary>${metric ? metricFacts(metric) : "<p>No primary score recorded.</p>"}
    ${alternatives.map(m => `<div class="sub-card"><strong>Alternative metric</strong>${metricFacts(m)}</div>`).join("")}</details></section>`;
}

function cveEvidence(row) {
  return `<section class="card"><h2>Evidence</h2>
    <details><summary>References</summary>${row.references?.some(safeUrl) ? `<ul>${row.references.filter(safeUrl).map(url =>
      `<li><a href="${escape(url)}" target="_blank" rel="noopener noreferrer">${escape(url)}</a></li>`).join("")}</ul>` : "<p>No references were recorded in this assessment.</p>"}</details></section>`;
}

function scenarioPanel(options, cve) {
  if (!options.length) return `<section class="card" id="scenarios"><h2>Architecture-aware assessment</h2>
    ${empty("No compatible saved scenario", "The selected CVE does not have a scenario in this evidence bundle.")}</section>`;
  return `<section class="card" id="scenarios"><h2>Architecture-aware assessment</h2>${scenarioChoices(options, cve)}</section>`;
}

function scenarioFacts(item, cve) {
  const date = item.live_evidence_at || (item.historical_snapshot_at
    ? item.historical_snapshot_at + " · historical snapshot generation" : windows(item.windows));
  return facts([
    ["Target", `${item.target} · ${item.target_deployment_id}`],
    ["Source deployment", item.sources.map(source => `${source.deployment_id} · ${source.version || "version unrecorded"}`).join(", ")],
    ["Evidence date", date], ["Scope", item.scope],
    ["Reproduction", (cve ? item.reproduction[cve] || [] : Object.values(item.reproduction).flat())
      .map(readable).join(", ") || "Unrecorded"],
  ]);
}

function scenarioChoices(options, cve) {
  const key = state.context + "Scenario";
  const selected = options.find(item => item.scenario_id === state.selected[key]) || options[0];
  state.selected[key] = selected.scenario_id;
  return `<label>Evidence-backed scenario<select id="scenario">${options.map(s => `<option value="${escape(s.scenario_id)}" ${selected === s ? "selected" : ""}>${escape(s.scenario_id)}</option>`).join("")}</select></label>
    <p>${escape(selected.description)}</p>
    ${scenarioFacts(selected, cve)}
    ${facts([["Attacker prerequisites", selected.attacker.description]])}
    ${list(selected.attacker.capabilities)}
    ${state.context === "historical" ? `<details><summary>Historical evidence dates and source paths</summary>${list(state.catalogs.historical.evidence_sources)}</details>` : ""}
    ${button("Evaluate scenario", "evaluate", state.busy ? "primary disabled" : "primary")}`;
}

function coverageKey(cve) {
  return `${state.server.assessment?.captured_at}/${cve}`;
}

function guidancePanel(guidance) {
  if (!guidance) return "";
  const guidanceStatus = value => value === "VERIFIED" ? "Verified"
    : value === "NOT_CONFIGURED" ? "Not configured"
    : value === "OBSERVED" ? "Observed"
    : value === "UNKNOWN" ? "Unknown"
    : labels[value] || readable(value);
  const next = guidance.next_action || {};
  const running = state.busy || state.server.job?.state === "running";
  const refresh = guidance.refresh_available
    ? button("Refresh read-only evidence", "refresh-analysis", running ? "disabled" : "primary")
    : "";
  const controlled = next.kind === "CONTROLLED_VALIDATION"
    ? '<a class="button" href="#experiment">Review bounded validation</a>' : "";
  const allLayers = [...(guidance.layers || []), ...(guidance.receiver ? [{...guidance.receiver, key: "receiver"}] : [])];
  const layers = allLayers.map(item =>
    `<div class="evidence-layer"><span>${escape(item.label)}</span><strong>${escape(guidanceStatus(item.status))}</strong></div>`).join("");
  return `<section class="evidence-guidance" aria-labelledby="guidance-title">
    <div class="guidance-head"><div><p class="eyebrow">Evidence-guided next step</p><h4 id="guidance-title">What is verified and what remains open</h4></div>
      <div class="guidance-actions">${controlled}${refresh}</div></div>
    <div class="evidence-layers">${layers}</div>
    <div class="guidance-columns"><div><strong>Verified by passive evidence</strong>${list(guidance.verified) || '<p class="muted">No architecture claim is verified yet.</p>'}</div>
      <div><strong>Still unknown</strong>${list(guidance.unknown)}</div></div>
    <div class="next-action"><strong>Recommended: ${escape(next.label || "Collect additional evidence")}</strong>
      <p>${escape(next.detail || "Additional evidence is required before drawing a conclusion.")}</p></div>
  </section>`;
}

function boundedContext(analysis) {
  return analysis?.bounded_context || analysis?.result?.bounded_context || null;
}

function boundedOutcomeStatus(analysis) {
  if (!boundedContext(analysis)) return "";
  return `<div class="message bounded-status" role="status">
    <strong>COMPONENT-BOUNDED ASSESSMENT — INCOMPLETE EVIDENCE</strong>
    <p>The available evidence supports a bounded component assessment. No numerical EBSR profile was calculated.</p>
  </div>`;
}

function boundedAssessmentPanel(analysis) {
  const context = boundedContext(analysis);
  if (!context) return "";
  const states = context.assessment_states || {};
  const stateItems = [
    ["Applicability", states.applicability],
    ["Architecture path", states.architecture_path],
    ["CVE-specific consequences", states.cve_specific_consequences],
    ["Numerical EBSR", states.engine],
  ].filter(([, item]) => item);
  const deployments = context.deployment || {};
  const position = context.architecture_position || {};
  const consequences = context.potential_consequence_categories || {};
  const cveEvidence = context.cve_specific_evidence || {};
  const relationships = context.relationships || [];
  const relationCards = relationships.length ? relationships.map(item => `<div class="relationship-card">
    <div><strong>${escape(item.source_product)} → ${escape(item.target_product)}</strong>
      <span class="status-badge">${escape(connectionLabels[item.verification] || readable(item.verification))}</span></div>
    <p>${escape(item.verification_reason)}</p>
    <p><b>Configuration:</b> ${escape(readable(item.configuration || "UNKNOWN"))} · <b>Observed communication:</b> ${escape(readable(item.communication || "UNKNOWN"))} · <b>CVE propagation:</b> NOT ESTABLISHED</p></div>`).join("")
    : '<p class="muted">No adjacent supported deployment pair was represented in this snapshot.</p>';
  return `<section class="live-finding component-bounded" aria-labelledby="bounded-title">
    <p class="eyebrow">Component-bounded assessment · no numerical risk</p>
    <h3 id="bounded-title">${escape(deployments.product || deployments.component_id || "Selected component")} ${escape(deployments.version || "")}</h3>
    <p>${escape(analysis.reason)}</p>
    <div class="bounded-states">${stateItems.map(([label,item]) => `<div class="evidence-layer">
      <span>${escape(label)}: ${escape(readable(item.classification || item.status))}</span>
      <strong>${escape(item.status)}</strong></div>`).join("")}</div>
    <div class="bounded-grid">
      <div><h4>Deployment and position</h4>${facts([
        ["Deployment", deployments.deployment_id || "Unrecorded"],
        ["Version", deployments.version || "Unrecorded"],
        ["Architecture position", position.label || "Unknown"],
        ["Terminal component", position.terminal_component ? "Yes, within supported scope" : "No"],
        ["Potential categories", consequences.categories?.join(", ") || "Unresolved"],
      ])}<p class="muted">${escape(consequences.reason || "")}</p></div>
      <div><h4>Known relationships</h4>${relationCards}</div>
    </div>
    <div class="guidance-columns">
      <div><strong>Known facts</strong>${list(context.known_facts)}</div>
      <div><strong>Missing evidence and limitations</strong>${list(context.missing_evidence)}</div>
    </div>
    <div class="next-action"><strong>Recommended evidence collection</strong>
      ${(context.recommended_actions || []).map(item => `<p><b>${escape(item.label)}</b> ${escape(item.detail)}</p>`).join("")}</div>
    <details><summary>Technical evidence and provenance</summary>
      ${facts(Object.entries(states).map(([key,item]) => [readable(key), `${item.status} · ${item.reason || ""}`]))}
      ${facts([["Discovery captured", (context.provenance || {}).discovery_captured_at],
               ["Assessment captured", (context.provenance || {}).assessment_captured_at],
               ["Applicability source", ((context.provenance || {}).applicability || {}).path]])}
      ${facts(Object.entries(cveEvidence).map(([key,item]) => [readable(key), `${item.status} · ${item.reason || ""}`]))}
      <p>Numerical EBSR status: <strong>${escape(context.numerical_assessment?.status || "NOT_CALCULATED")}</strong>. ${escape(context.numerical_assessment?.reason || "")}</p>
      <pre>${escape(JSON.stringify(context.provenance || {}, null, 2))}</pre>
    </details>
  </section>`;
}

function refreshNotice() {
  const job = state.server.job;
  if (job?.kind !== "refresh") return "";
  if (job.state === "running") return `<div class="message" role="status"><span class="progress"></span>${escape(job.message)}</div>`;
  if (job.state === "error") return `<div class="message error" role="alert">${escape(job.message)}</div>`;
  return `<div class="message"><strong>Refresh ${escape(readable(job.refresh_status))}</strong> / ${escape(job.message)}</div>`;
}

function generatedPanel(cve) {
  const analysis = state.analysis;
  const experiment = state.coverage?.key === coverageKey(cve)
    ? state.coverage.related.find(item => item.context === "experiment") : null;
  const related = relatedControlledEvidence(cve, experiment);
  if (analysis?.key !== coverageKey(cve)) return related;
  if (analysis.pending) return '<p role="status">Matching discovered components and evaluating the deployment scenario…</p>';
  const r = analysis.result;
  const routes = r?.routes || analysis.routes || [];
  const options = routes.map((ids,i) => {
    const name = ids.map(id => {
      const row = state.server.discovery.supported.find(d => d.deployment_id === id);
      return row ? row.product + " " + row.version + " (" + id + ")" : id;
    }).join(" → ");
    return `<option value="${i}" ${JSON.stringify(ids) === JSON.stringify(r?.route) ? "selected" : ""}>${escape(name)}</option>`;
  });
  const editor = options.length ? `<details ${r ? "" : "open"}><summary>Confirm or change the intended route</summary>
    <label>Discovered deployments<select id="live-route">${options.join("")}</select></label>
    <label>Evidence for the final connection<select id="route-assertion"><option value="">Use discovery evidence</option><option value="intended">I confirm the intended connection</option><option value="configuration">I reviewed the endpoint configuration</option></select></label>
    <label>Evidence record ID or filename (optional)<input id="route-reference" maxlength="80" placeholder="e.g. connection-review-01"></label>
    ${button("Evaluate this route","confirm-route")}</details>` : "";
  if (!r) return `${refreshNotice()}${boundedAssessmentPanel(analysis)}${analysis.bounded_context ? "" : `<p>${escape(analysis.reason)}</p>`}${guidancePanel(analysis.guidance)}${related}${analysis.failed ? button("Retry architecture assessment","retry-analysis") : ""}${editor}`;
  const impact = r.paths[0].target_impact;
  return `<section class="live-finding"><h3>${r.component_level ? "Component-level assessment" : "Candidate architecture target"} · ${escape(r.target_product)} ${escape(r.target_version)}</h3>
    ${refreshNotice()}${guidancePanel(r.evidence_guidance)}${related}
    <p>${r.component_level ? "The CVE is applicable to the selected deployment. CVE-specific capability and component target consequences remain unverified; no downstream component is inferred." : `The selected CVE affects ${escape(state.server.assessment.deployment.product)} ${escape(state.server.assessment.deployment.version)}. Its effect on this route remains unverified.`}</p>
    <div class="evidence-map" aria-label="Discovered application route">
    ${r.snapshot.connections.map(edge => `<details class="edge-${escape(edge.verification || "UNKNOWN")}"><summary>
      <span class="status-badge">Connection status: ${escape(connectionLabels[edge.verification] || readable(edge.verification || "UNKNOWN"))}</span>
      <strong>${escape(edge.source_product || edge.source)} → ${escape(edge.target_product || edge.target)}</strong>
      <span>${escape(edge.basis)}</span></summary>
      <p>${escape(edge.verification_reason || edge.verification_meaning || "")}</p>
      <p><strong>Vulnerability propagation:</strong> ${escape(readable(edge.propagation || "UNKNOWN"))}.</p>
      <p><strong>Next action:</strong> ${escape(edge.next_action || "Additional evidence is required.")}</p>
      ${facts([["Deployment identities",edge.source+" → "+edge.target],["Shared networks",edge.shared_networks.join(", ") || "None recorded"],
               ["Endpoint settings",edge.matching_endpoint_settings.join(", ") || "None matched"],
               ["Configuration",readable(edge.configuration || "Unknown")],["Communication",readable(edge.communication || "Unknown")],
               ["CVE-specific propagation","Not verified"],["Operator reference",edge.operator_reference || "None supplied"]])}
      ${(edge.inventory || []).map(item=>facts([["Connection inventory",readable(item.status)],["Reason",item.reason || "Unrecorded"],["Records",item.total_connections ?? "Unknown"]])).join("")}
      ${(edge.records||[]).map(item=>facts([["Endpoint",item.endpoint],["Source",item.source],["Observed UTC",item.timestamp]])).join("")}
      <p>${escape(edge.limitation || "")}</p></details>`).join("")}</div>
    <p class="graph-key">Configuration verified · Communication observed · Shared network only · No matching configuration · Unknown</p>
    <p><strong>Conditional feasibility</strong> · ${r.feasibility_envelope ? bounds(r.feasibility_envelope) : "Unquantified with the available inputs"}. This interval is a model bound, not a probability.</p>
    <p>${Object.entries({C:"Confidentiality",I:"Integrity",A:"Availability"}).map(([k,title])=>title + ": " + escape(labels[impact[k].status] || readable(impact[k].status))).join(" · ")}</p>
    <p><strong>Observed downstream impact:</strong> ${escape(readable(r.evidence_guidance?.layers?.find(item => item.key === "impact")?.status || "UNKNOWN"))}. Connectivity and ordinary traffic do not establish a CVE-specific effect.</p>
    ${r.snapshot.prerequisite_findings?.length ? `<details><summary>Broker prerequisites and controls</summary>${list(r.snapshot.prerequisite_findings)}</details>` : ""}
    ${editor}<details><summary>Advanced Technical Details</summary>${resultPanel(r)}${facts([["Scenario bundle",r.provenance.path],["SHA-256",r.provenance.sha256]])}</details></section>`;
}

async function analyzeSelected(cve, route, assertion, reference) {
  const assessment = state.server.assessment;
  const key = coverageKey(cve);
  state.analysis = {key,pending:true};
  render();
  try {
    const data = await api("/api/analyze", {cve,route,assertion,reference,deployment_id:assessment.deployment.deployment_id,
      captured_at:assessment.captured_at});
    if (coverageKey(state.selected.liveCve) !== key) return;
    state.analysis = {key,...data};
    if (data.report) state.reports.live = data.report;
    if (data.result) {
      state.server.results.live = data.result;
      state.selected.liveScenario = data.result.scenario_id;
    }
  } catch (error) {
    if (coverageKey(state.selected.liveCve) === key) state.analysis = {key,failed:true,reason:error.message};
  } finally { if (state.context === "live") render(); }
}

function relatedControlledEvidence(cve, experiment) {
  if (cve !== "CVE-2018-12546") return "";
  const link = experiment
    ? `#experiment/${encodeURIComponent(experiment.scenario_id)}/${encodeURIComponent(cve)}/evidence`
    : "#experiment";
  if (state.experimentalEvidenceError) {
    return `<section class="card controlled-evidence"><h2>Related Controlled Experimental Evidence</h2>
      <div class="message error" role="alert">${escape(state.experimentalEvidenceError)}</div>
      <p>The live assessment and its EBSR result are unchanged. Restore the saved experiment artifacts and reload this page.</p>
      <a class="button" href="${link}">Open experiment page</a></section>`;
  }
  const runs = state.evidence?.runs || [];
  const broker = runs.find(run => run.number === 1 && run.cve === cve);
  const flow = runs.find(run => run.number === 2 && run.cve === cve);
  if (!broker || !flow) {
    if (!experiment) return "";
    return `<section class="card controlled-evidence"><h2>Related Controlled Experimental Evidence</h2>
      <div class="message warning" role="status">The related saved experiment is identified, but its detailed evidence could not be loaded.</div>
      <p>The current live assessment remains unchanged. Open the experiment page after restoring its evidence files.</p>
      <a class="button" href="${link}">Open experiment page</a></section>`;
  }
  const vulnerableBroker = broker.arms.vulnerable;
  const controlBroker = broker.arms.control;
  const vulnerableFlow = flow.arms.vulnerable;
  const controlFlow = flow.arms.control;
  const cleanup = [vulnerableBroker, controlBroker, vulnerableFlow, controlFlow]
    .every(arm => arm.cleanup === "VERIFIED");
  const rows = count => `${count} retained-marker row${count === 1 ? "" : "s"}`;
  const yes = value => value ? "Verified" : "Not verified";
  return `<section class="card controlled-evidence" aria-labelledby="controlled-evidence-title">
    <div class="section-head"><div><p class="eyebrow">Related research evidence</p><h2 id="controlled-evidence-title">Related Controlled Experimental Evidence</h2>
      <p>An isolated paired study that tested whether a retained command crosses application boundaries after publisher access is revoked.</p></div>
      <a class="button" href="${link}">Open experimental evidence</a></div>
    <div class="scope-callout"><strong>Historical results from isolated temporary deployments.</strong>
      <span>They are not evidence of exploitation in the currently selected live deployment. The live EBSR states and target C/I/A remain unchanged.</span></div>
    <div class="finding-lede"><span class="context-tag">Main finding</span>
      <p>The vulnerable configuration delivered the retained command after revocation, changed the isolated Ditto Thing, and produced matching InfluxDB records. The configured control held the command while authorized traffic continued to work.</p></div>
    <div class="experiment-arms">
      <article class="arm-card arm-vulnerable"><div class="arm-title"><span class="status bad">Observed propagation</span><h3>Vulnerable arm</h3></div>
        <ul><li><strong>Mosquitto ${escape(vulnerableBroker.version)}:</strong> retained-message policy violation observed after verified publisher revocation.</li>
          <li><strong>Eclipse Ditto:</strong> isolated Thing changed from ${escape(vulnerableFlow.initial_temperature)} to ${escape(vulnerableFlow.retained_temperature)}.</li>
          <li><strong>InfluxDB:</strong> readback confirmed ${rows(vulnerableFlow.records)} for the retained marker.</li></ul></article>
      <article class="arm-card arm-control"><div class="arm-title"><span class="status good">Control policy held</span><h3>Control arm</h3></div>
        <ul><li><strong>Mosquitto ${escape(controlBroker.version)}:</strong> retained command withheld with <code>check_retain_source=${escape(controlBroker.source_check)}</code>.</li>
          <li><strong>Eclipse Ditto:</strong> no corresponding Thing change in the observation window.</li>
          <li><strong>InfluxDB:</strong> no retained-marker rows in the verified query window.</li></ul></article>
    </div>
    <div class="experiment-controls">${facts([
      ["Normal flow", yes(vulnerableFlow.normal_verified && controlFlow.normal_verified)],
      ["Post-control flow", yes(vulnerableFlow.post_control_verified && controlFlow.post_control_verified)],
      ["Cleanup", cleanup ? "Verified for both arms" : "Not fully verified"],
      ["Evidence scope", "Temporary experimental deployments"]])}</div>
    <details><summary>Technical evidence and provenance</summary>
      <div class="two-col"><div class="sub-card"><h3>Experiment 1 - broker policy</h3>${facts([
        ["Observation window", windows([broker.window])], ["Vulnerable deployment", vulnerableBroker.deployment],
        ["Control deployment", controlBroker.deployment], ["Control source check", controlBroker.source_check || "Not explicit"],
        ["Vulnerable stale deliveries", vulnerableBroker.counts?.stale_original_marker],
        ["Control stale deliveries", controlBroker.counts?.stale_original_marker]])}
        <p class="provenance"><a href="/evidence-source/run1.json" target="_blank" rel="noopener">${escape(broker.source.path)}</a></p>
        <p class="provenance">SHA-256 ${escape(broker.source.sha256)}</p></div>
      <div class="sub-card"><h3>Experiment 2 - downstream consequence</h3>${facts([
        ["Observation window", windows([flow.window])], ["Vulnerable deployment", vulnerableFlow.deployment],
        ["Control deployment", controlFlow.deployment], ["Vulnerable Thing", vulnerableFlow.thing_id],
        ["Control Thing", controlFlow.thing_id], ["Vulnerable marker", vulnerableFlow.marker],
        ["Control marker", controlFlow.marker], ["Readback status", state.evidence.readback.status]])}
        <p class="provenance"><a href="/evidence-source/run2.json" target="_blank" rel="noopener">${escape(flow.source.path)}</a></p>
        <p class="provenance">SHA-256 ${escape(flow.source.sha256)}</p></div></div>
      <details><summary>InfluxDB readback rows</summary>${facts(state.evidence.readback.rows.map(row => [row.time, `${row.value} / ${row.run_marker} / ${row.thing_id}`]))}
        <p class="provenance"><a href="/evidence-source/readback.json" target="_blank" rel="noopener">${escape(state.evidence.readback.source.path)}</a></p>
        <p class="provenance">SHA-256 ${escape(state.evidence.readback.source.sha256)}</p></details>
      <p class="provenance">Scenario ${escape(experiment?.scenario_id || "not recorded in this response")} / readback verified ${escape(state.evidence.readback.verified_at_utc)}</p>
    </details>
    <details><summary>Limitations</summary><ul>
      <li>Duplicate-row causation was not established. The vulnerable arm has two matching rows, but the experiment does not prove why duplication occurred.</li>
      <li>The numerical magnitude of security impact was not measured. The Thing value change is an observed integrity consequence, not a normalized C/I/A magnitude.</li>
      <li>Results are limited to the recorded temporary deployments, event markers, targets and observation windows.</li>
    </ul></details></section>`;
}

function liveCoverage(cve) {
  const info = state.coverage?.key === coverageKey(cve) ? state.coverage : null;
  const experiment = info?.related.find(item => item.context === "experiment");
  const scenarioLink = item => `#${item.context}/${encodeURIComponent(item.scenario_id)}/${encodeURIComponent(cve)}`;
  const analysis = state.analysis?.key === coverageKey(cve) ? state.analysis : null;
  const generated = Boolean(analysis?.result);
  const bounded = Boolean(boundedContext(analysis));
  const assessed = generated || bounded;
  const labOnly = !assessed && experiment && info.coverage === "related" && !info.compatible.length;
  const experimentLink = experiment && "#architecture/" + encodeURIComponent(experiment.scenario_id);
  const deployment = state.server.assessment?.deployment;
  const components = ["IoMT Device","Mosquitto","Eclipse Ditto","InfluxDB","Healthcare Monitoring"];
  const origin = components.findIndex(name => name.toLowerCase() === deployment?.product?.toLowerCase());
  const active = state.selected.routeNode || deployment?.product;
  const nodeIndex = components.indexOf(active);
  const discovered = state.server.discovery?.supported.filter(item => item.product === active) || [];
  const versionNote = discovered.map(item => item.version + " · " + item.deployment_id).join(", ");
  const node = analysis?.result?.snapshot?.nodes?.find(n=>n.product === active);
  const inspections = (node?.inspections || []).map(entry => {
    const cfg = entry.mosquitto_file;
    return facts([["Source", cfg?.source || "Docker inspection and available service observations"],
      ["Collection time", entry.finished],["Declared settings",cfg ? Object.entries(cfg.directives).map(([k,v])=>k+"="+v).join(", ") || "None recognized" : "See service evidence"],
      ["Recent activity",Object.entries(entry.log_events || {}).map(([k,v])=>readable(k)+": "+v).join(", ") || "Unavailable"],
      ["Connection inventory",entry.connection_inventory ? readable(entry.connection_inventory.status) : "Unavailable"],
      ["Inventory records",entry.connection_inventory?.total ?? entry.connections?.length ?? "Unknown"],
      ["Bucket / organization records",entry.influx_metadata ? [entry.influx_metadata.buckets?.length ?? "unknown",entry.influx_metadata.orgs?.length ?? "unknown"].join(" / ") : "Not inspected"]]);
  }).join("");
  const routeNote = nodeIndex === 4 ? "Healthcare Monitoring is conceptual downstream context. Clinical effects have not been validated."
    : nodeIndex === 0 ? "The device is represented in the laboratory by a publisher."
    : nodeIndex === origin ? "The scan evaluated this component’s software version for applicability."
    : nodeIndex > origin && origin > 0 ? "This is a possible downstream target on the configured route. Its exposure requires deployment-specific evidence."
    : "This component belongs to the configured architecture. Its role in this CVE requires separate evidence.";
  const explanation = "Vulnerability applicability has been assessed. Architecture-aware evaluation requires evidence matching this deployment.";
  const coverageText = {related: "Related scenarios use a different evidence scope.", none: "No scenario was found for this CVE and product.", unavailable: "Scenario coverage could not be fully checked."};
  return `<section class="card" id="scenarios"><h2>Architecture-aware assessment</h2><div class="configured-route" aria-label="Configured architecture">${components.map((name,index)=>`<button data-action="route-node" data-value="${name}" aria-pressed="${name === active}">${name}</button>${index<4 ? '<span aria-hidden="true">→</span>' : ""}`).join("")}</div><p class="route-caption">${escape(versionNote)} ${escape(routeNote)}${state.analysis?.result?.target_product === active ? " Selected target · impact unknown; target vulnerability scan not performed in this assessment." : ""}</p>${node ? `<details><summary>${escape(active)} inspection evidence</summary>${inspections || "<p>No verified service observations in this snapshot.</p>"}${list(node.issues)}</details>` : ""}${generatedPanel(cve)}${labOnly ? `<div class="lab-context">
      <h3>Live deployment risk assessment not yet available</h3>
      <p>We have validated this CVE in separate laboratory deployments. Those results are available below, but do not automatically apply to this running container.</p>
      <a class="button primary" href="${experimentLink}">View Experimental Evidence</a>
      <small>Live EBSR status: <code>NOT_ASSESSED</code></small>
    </div><details><summary>Evidence needed for this deployment</summary>${list(info.missing)}</details>` : assessed ? "" : `<p>${explanation}</p>`}
    ${!info ? '<p>Checking scenario coverage…</p>' : ""}
    ${info?.compatible.length ? `<h3>Compatible deployment-scoped scenarios</h3>${scenarioChoices(info.compatible, cve)}` : ""}
    ${bounded ? boundedOutcomeStatus(analysis) : ""}
    ${info?.coverage && !assessed && !labOnly && !info.compatible.length ? `<div class="message warning"><strong>NOT_ASSESSED</strong> · ${coverageText[info.coverage] || "No compatible scenario was available."}</div>
      ${list(info.missing)}<p>Continue to your report for the applicability findings and evidence gaps.</p>` : ""}
    ${info?.errors.map(item => `<div class="message error" role="alert">${escape(titles[item.context])} · ${escape(item.message)}
      <p>${button("Retry scenario lookup", "retry-coverage")}</p></div>`).join("") || ""}
    ${experiment && !labOnly ? `<p>Paired experiments are recorded evidence from temporary deployments.</p><a class="button" href="${experimentLink}">View Experimental Evidence</a>` : ""}
    ${info?.out_of_scope?.map(item => `<details><summary>${escape(item.scenario_id)} · Evidence scope does not match</summary>${scenarioFacts(item, cve)}</details>`).join("") || ""}
    ${info?.related.length ? `<details><summary>Other saved scenario details</summary>${info.related.map(item => `<details><summary>${escape(item.scenario_id)} · ${escape(titles[item.context])}</summary>
      ${scenarioFacts(item, cve)}
      <a class="button" href="${scenarioLink(item)}">${item.context === "experiment" ? "Open experimental scenario" : "View historical scenario"}</a></details>`).join("")}</details>` : ""}
    </section>`;
}

async function loadCoverage(cve) {
  const key = coverageKey(cve);
  state.coverage = null;
  const requests = [api("/api/coverage?cve=" + encodeURIComponent(cve))];
  const loadExperiment = cve === "CVE-2018-12546" && !state.evidence;
  if (loadExperiment) requests.push(api("/api/evidence"));
  const [coverageResult, evidenceResult] = await Promise.allSettled(requests);
  if (coverageKey(state.selected.liveCve) !== key) return;
  if (coverageResult.status === "fulfilled") {
    state.coverage = {...coverageResult.value, key};
  } else {
    state.coverage = {key, coverage: "unavailable", compatible: [], related: [], missing: [],
      errors: [{context: "live", message: coverageResult.reason.message}]};
  }
  if (loadExperiment) {
    if (evidenceResult.status === "fulfilled") {
      state.evidence = evidenceResult.value;
      state.experimentalEvidenceError = "";
    } else {
      state.experimentalEvidenceError = evidenceResult.reason.message;
    }
  }
  if (state.context === "live") render();
}

function conditionEvidence(item) {
  return `${list(item.reason)}${item.sources.map(source => `<div class="sub-card">
    <strong>${escape(readable(source.evidence_class || "Evidence source"))}</strong>
    ${list(source.evidence)}
    <p class="provenance">${escape(source.supporting_artifact || source.source)}</p>
    ${source.observation_window_utc ? `<p class="provenance">${escape(windows([source.observation_window_utc]))}</p>` : ""}
    </div>`).join("")}`;
}

function resultPanel(result) {
  if (!result || result.status === "NOT_ASSESSED") return "";
  return `<section class="card" id="results"><div class="section-head"><div><h2>Evaluation results</h2>
    <p>${escape(result.scenario_id)} · ${escape(result.target_component)}</p></div>${status(result.status)}</div>
    <div class="result-section"><h3>Feasibility</h3>
    ${facts([["Conditional model bounds", bounds(result.feasibility_envelope)], ["Evaluated UTC", result.captured_at]])}
    <p>These bounds express conditional model feasibility. They do not represent an attack probability.</p></div>
    ${result.paths.map(path => `<div class="sub-card"><h3>${escape(path.path_id)}</h3>
      <div class="result-section"><h3>Evaluated route</h3>${architecture(path, result.reproduction_scope.filter(item => item.path_id === path.path_id))}</div>
      <div class="result-section"><h3>Target confidentiality, integrity and availability</h3>
      <div class="facts">${Object.entries(path.target_impact).map(([channel, item]) =>
        `<div class="metric"><strong>${escape(labels[item.status] || readable(item.status))}</strong>
        <small>${{C:"Confidentiality", I:"Integrity", A:"Availability"}[channel]} · ${bounds(item.interval)}</small></div>`).join("")}</div></div>
      <div class="result-section"><h3>Evidence quality</h3>
        ${facts([["Source reproduction", result.reproduction_scope.filter(item => item.path_id === path.path_id)
          .map(item => readable(item.source_observation_grade)).join(", ") || "Unrecorded"],
        ["Evidence bundle", result.provenance?.path]])}</div>
      <div class="result-section"><h3>Evidence trace</h3>
      <details><summary>Target C/I/A evidence</summary>
        ${Object.entries(path.target_evidence).map(([key, item]) => `<div class="sub-card"><strong>${{C:"Confidentiality",I:"Integrity",A:"Availability"}[key]}</strong>${conditionEvidence(item)}</div>`).join("")}</details>
      ${path.transitions.map(step => `<details><summary>${escape(step.transition_type)} · ${escape(step.source)} to ${escape(step.target)} · A/G/H/B/K/Y</summary>
      ${Object.entries(step.conditions).map(([key, item]) => `<details><summary>${key} · ${escape(item.meaning)} · ${status(`${item.status} ${labels[item.status] || ""}`)}</summary>${item.definition ? `<p>${escape(item.definition)}</p>` : ""}${item.proposition_id ? `<p>Proposition <code>${escape(item.proposition_id)}</code></p>` : ""}${conditionEvidence(item)}</details>`).join("")}</details>`).join("")}
      </div></div>`).join("")}
    <details><summary>How to read these results</summary><p>UNKNOWN means evidence is insufficient to establish an outcome. UNQUANTIFIED means the numerical magnitude remains undetermined. ZERO means the model bounds the scenario at zero under the stated conditions. An unknown outcome or undetermined magnitude does not establish safety.</p></details></section>`;
}

function evidencePanel(selected) {
  const evidence = state.evidence;
  if (!evidence) return empty("Experimental evidence unavailable", "Reload this context after restoring the saved run and readback files.");
  return `<section class="card"><h2>Paired experiment evidence</h2><p>Two experiments on one CVE. Temporary broker deployments and bounded event windows.</p>
    ${selected ? `<p><strong>${escape(selected.scenario_id)}</strong></p>${scenarioFacts(selected, state.experimentCve)}` : ""}
    ${evidence.runs.filter(run => !selected || run.cve === state.experimentCve).map(run => `<details ${selected ? "open" : ""}><summary>Experiment ${run.number} · ${run.number === 1 ? "Broker retained delivery" : "Ditto and InfluxDB propagation"}</summary>
      <h3>Research question</h3><p>${run.number === 1 ? "Does the broker deliver a previously retained marker after publisher authorization is revoked?" : "Does the retained marker produce a measurable change in the isolated Ditto Thing and InfluxDB?"}</p>
      <p class="provenance">${escape(run.cve)} · ${escape(windows([run.window]))}</p>
      <h3>Tested configurations and observed results</h3>
      <div class="two-col">${Object.entries(run.arms).map(([arm, data]) => `<div class="sub-card"><h3>${arm === "control" ? "Control" : "Vulnerable"}</h3>
        ${facts([["Broker version", data.version], ["Deployment ID", data.deployment], ["Source check", data.source_check ? "check_retain_source=" + data.source_check : "No explicit setting recorded"],
          ["Broker settings", Object.entries(data.settings).map(([key, value]) => key + "=" + value).join(" · ")], ["Outcome", readable(data.outcome)],
          ["Cleanup", data.cleanup], ["Marker", data.marker], ...(data.counts ? [["Initial delivery", data.counts.initial], ["Retained marker delivery after revocation", data.counts.stale_original_marker], ["Authorized replacement delivery", data.counts.replacement_marker]] :
            [["Thing ID", data.thing_id], ["Thing changed", data.thing_changed], ["Writer event", data.writer_event],
              ["Retained marker rows", data.records], ["Normal flow verified", data.normal_verified],
              ["Post-control verified", data.post_control_verified], ...(data.marker_window ? [["Retained observation", windows([data.marker_window])]] : [])])])}
        ${data.rows?.length ? facts(data.rows.map(row => [row.time, row.value])) : ""}</div>`).join("")}</div>
      <p class="provenance"><a href="/evidence-source/run${run.number}.json" target="_blank" rel="noopener">${escape(run.source.path)}</a> · curated source fields</p>
      <p>Conclusions apply to the recorded broker configuration and observation window.</p></details>`).join("")}
    <details><summary>InfluxDB readback and control window</summary>
    ${facts([["Readback status", evidence.readback.status], ["Verified UTC", evidence.readback.verified_at_utc], ["Control window", windows([evidence.readback.window])]])}
    ${facts(evidence.readback.rows.map(row => [row.time, `${row.value} · ${row.run_marker} · ${row.thing_id}`]))}
    <p class="provenance"><a href="/evidence-source/readback.json" target="_blank" rel="noopener">${escape(evidence.readback.source.path)}</a> · curated source fields</p>
    </details><details><summary>Cleanup and limitations</summary><p>Cleanup statuses are reported for each arm. These results cover the recorded deployments and events. The cause of duplicate rows and the numerical magnitude of impact remain unmeasured.</p></details></section>`;
}

const scopeName = context => ({live:"Live deployment", historical:"Saved historical evidence", experiment:"Recorded experiment"}[context]);

function recentReports() {
  if (!state.reportIndex) return "<p>Loading saved reports…</p>";
  if (!state.reportIndex.length) return "<p>Reports will appear here once you save an assessment or evaluation.</p>";
  return `<ul class="report-list">${state.reportIndex.filter(item => !item.archived).slice(0, 3).map(item => `<li>
    <div><a href="/reports/${escape(item.report_id)}.html?view=1" target="_blank" rel="noopener">${escape(item.title)}</a>
    <small>${escape(item.scope)} · ${escape(item.captured_at || item.saved_at_utc || "Unrecorded")}</small></div>${status(item.status)}</li>`).join("")}</ul>`;
}

function homePage() {
  return homeTemplate + (state.reportIndex?.some(item => !item.archived) ?
    `<section class="recent"><div class="section-head"><h2>Recent assessments</h2><a href="#reports">All reports</a></div>${recentReports()}</section>` : "");
}

function reportsPage() {
  const scopes = [["", "All scopes"], ["live", "Live deployment"], ["historical", "Historical evidence"], ["experiment", "Recorded experiment"]];
  return `<div class="hero"><div><h1>Reports</h1><p>Open previously saved assessments and download their evidence summaries.</p></div></div>
    <section class="card"><h2>Saved reports</h2>
    <div class="controls"><label>Search reports<input id="report-query" type="search" value="${escape(state.reportQuery || "")}" placeholder="Title, component, version or status"></label>
    <label>Scope<select id="report-scope">${scopes.map(([value, label]) => `<option value="${value}" ${state.reportScope === value ? "selected" : ""}>${label}</option>`).join("")}</select></label></div>
    <label class="archive-switch"><input type="checkbox" id="include-archives" ${state.includeArchives ? "checked" : ""}> Include historical CLI snapshots and replays</label><div id="report-table"></div>${state.reportIssues?.length ? `<details><summary>Unreadable or unsupported artifacts (${state.reportIssues.length})</summary>${list(state.reportIssues)}</details>` : ""}</section>`;
}

function reportTable() {
  const target = document.querySelector("#report-table");
  if (!target) return;
  if (state.reportError) {
    target.innerHTML = `<div class="message error">${escape(state.reportError)} <button class="button" data-action="retry-reports">Retry</button></div>`;
    return;
  }
  if (!state.reportIndex) {
    target.innerHTML = "<p>Loading saved reports…</p>";
    return;
  }
  const query = (state.reportQuery || "").trim().toLowerCase();
  const rows = state.reportIndex.filter(item => (state.includeArchives || !item.archived) && (!state.reportScope || state.reportScope === item.context)
    && [item.title, item.product, item.version, readable(item.display_status || item.status), item.scope].join(" ").toLowerCase().includes(query));
  target.innerHTML = rows.length ? `<div class="table-wrap"><table><thead><tr><th>Title</th><th>Component / version</th><th>Capture / evaluation UTC</th><th>Scope</th><th>Status</th><th>Exports</th></tr></thead>
    <tbody>${rows.map(item => `<tr><td><a href="/reports/${escape(item.report_id)}.html?view=1" target="_blank" rel="noopener">${escape(item.title)}</a></td>
    <td>${escape(item.product)} · ${escape(item.version)}</td><td>${escape(item.captured_at || item.saved_at_utc || "Unrecorded")}</td>
    <td>${escape(item.scope)}${item.assessment_type ? `<details><summary>${escape(item.assessment_type)}</summary>${facts([["Run ID",item.report_id],["Deployment",item.deployment_id],["CVE",item.cve]])}</details>` : ""}</td><td>${status(item.display_status || item.status)}${item.retrieval ? `<br><small>Retrieval ${escape(readable(item.retrieval))}</small>` : ""}</td>
    <td><div class="report-links"><a href="/reports/${escape(item.report_id)}.html">HTML</a><a href="/reports/${escape(item.report_id)}.json">JSON</a></div></td></tr>`).join("")}</tbody></table></div>`
    : empty(state.reportIndex.length ? "No matching reports" : "No reports saved", state.reportIndex.length ? "Change the search or scope filter." : "Save an assessment or scenario evaluation to add it here.");
}

function assessmentPage(context, rows, cve, result) {
  const live = context === "live";
  const current = state.server.assessment;
  const assessment = live && (!state.selected.liveDeployment || current?.deployment.deployment_id === state.selected.liveDeployment) ? current : null;
  if (live && !assessment) { result = null; cve = null; }
  const historical = state.catalogs.historical;
  const selected = state.server.discovery?.supported.find(item => item.deployment_id === state.selected.liveDeployment);
  const step = state.steps[context];
  const liveAnalysis = live && cve && state.analysis?.key === coverageKey(cve.cve_id) ? state.analysis : null;
  const pending = state.busy || state.server.job?.state === "running";
  const steps = [
    [step === "deployments" || (!assessment && !selected && live) ? "deployments" : "vulnerabilities", "Scan system", true],
    ["scenarios", "Analyze architecture risk", Boolean(cve)],
    ["review", "Results &amp; report", Boolean(assessment || result)],
  ];
  const deployment = live ? (step === "deployments" ? selected : assessment?.deployment || selected)
    : cve?.deployment || historical?.rows?.[0]?.deployment;
  let body = "";
  if (step === "deployments" && live) body = `<div class="section-head"><h2>Select deployment</h2>${button("Discover deployments", "discover", pending ? "primary disabled" : "primary")}</div>${deploymentsPanel()}`;
  if (step === "vulnerabilities") {
    body = (live && selected ? `<section class="card"><div class="section-head"><div><h2>Assess vulnerabilities</h2><p>${escape(selected.product)} ${escape(selected.version)} · ${escape(selected.deployment_id)}</p></div>
    ${button("Run vulnerability assessment", "assess", pending ? "primary disabled" : "primary")}</div>
    ${state.server.job?.state === "running" ? `<p><span class="progress"></span>${escape(state.server.job.message)}</p>` : ""}
    ${state.server.job?.state === "error" ? `<div class="message error">${escape(state.server.job.message)}</div>` : ""}</section>` : "")
      + ((assessment && (!selected || selected.deployment_id === assessment.deployment.deployment_id) || (!live && historical)) ? vulnerabilityPanel(rows, assessment) : "");
  }
  if (step === "scenarios" && cve) body = `<div class="finding-intro"><strong>${escape(cve.cve_id)}</strong> · ${escape(readable(cve.status))}<p>${escape(cve.description || cve.reason || "")}</p></div>` + (live ? liveCoverage(cve.cve_id)
    : scenarioPanel((historical?.scenarios || []).filter(item => item.cves.includes(cve.cve_id)), cve.cve_id)) + `<details class="card"><summary>Advanced Technical Details</summary>${details(cve)}${cveEvidence(cve)}</details>`;
  if (step === "review") body = (liveAnalysis && (liveAnalysis.result || boundedContext(liveAnalysis)) ? generatedPanel(cve.cve_id) + boundedOutcomeStatus(liveAnalysis) : result?.snapshot ? `<section class="card"><h2>Architecture finding</h2><p>${escape(result.description)}</p><p>${escape(scopeName(context))}</p></section><details class="card"><summary>Advanced Technical Details</summary>${resultPanel(result)}</details>` : result && result.status !== "NOT_ASSESSED" ? `<section class="card"><h2>Architecture finding</h2><p>${escape(result.description)}</p><p>${escape(scopeName(context))}</p></section><details class="card"><summary>Advanced Technical Details</summary>${resultPanel(result)}</details>` :
    `<section class="card"><h2>Assessment summary</h2><p>${assessment ? "The scan result is recorded. Downstream risk remains unassessed for this deployment. Confirm the route, access conditions and target effects to evaluate it." : "Evaluate a saved scenario to create a report."}</p>
    ${assessment ? facts([["Retrieval status", readable(assessment.retrieval.status)],
    ["Classified candidates", assessment.rows.length], ["Captured UTC", assessment.captured_at],
    ...(cve ? [["CVE applicability", `${cve.cve_id} · ${readable(cve.status)}`]] : [])]) : ""}</section>`)
    + ((assessment || result) ? exportPanel() : "");
  return `<div class="hero"><div><h1>${step === "review" ? "Results &amp; report" : step === "scenarios" ? "Analyze architecture risk" : "Scan system"}</h1><p>${step === "review" ? "Review the evidence and export your findings." : step === "scenarios" ? "Trace possible downstream effects and see which ones the evidence supports." : "Discover a running deployment, then scan its software version for applicable vulnerabilities."}</p></div></div>
    <div class="context-strip"><strong>${escape(scopeName(context))}</strong>
      ${deployment ? `<span>${escape(deployment.product)} ${escape(deployment.version)}</span><span class="mono">${escape(deployment.deployment_id)}</span>` : ""}
      <span>${cve ? escape(cve.cve_id) : "No CVE selected"}</span></div>
    <div class="steps" aria-label="Assessment steps">${steps.map(([key, label, enabled], index) => `<button type="button" class="button" data-action="step" data-value="${key}"
      ${key === step ? 'aria-current="step"' : ""} ${!enabled ? "disabled" : ""}>${index + 1}. ${label}</button>`).join("")}</div>
    ${body}
    ${step === "scenarios" && assessment ? '<button class="button" data-action="step" data-value="review">Continue to report</button>' : ""}
    ${step === "deployments" ? '<p class="secondary-path"><a href="#architecture">Explore a saved laboratory assessment</a> · <a href="#historical">Historical assessment inputs</a></p>' : ""}
    ${live && step === "vulnerabilities" ? '<button class="button" data-action="step" data-value="deployments">Change deployment</button>' : ""}`;
}

function experimentPage(catalog, result) {
  const evaluation = state.experimentView === "evaluation";
  const selected = state.experimentCve && catalog?.scenarios.find(item =>
    item.scenario_id === state.selected.experimentScenario && item.cves.includes(state.experimentCve));
  return `<div class="hero"><div><h1>${!evaluation && state.experimentCve ? "Saved experimental evidence" : "Experiments"}</h1><p>Compare two recorded experiments on CVE-2018-12546.</p></div></div>
    <p class="scope-note">Recorded experimental configuration. These findings are not automatically an assessment of the selected live deployment.</p>
    <div class="subnav"><a class="button" href="#architecture${state.selected.experimentScenario ? "/" + encodeURIComponent(state.selected.experimentScenario) : ""}">View architecture risk assessment</a><button class="button ${evaluation ? "" : "primary"}" data-action="experiment-view" data-value="evidence" aria-pressed="${!evaluation}">Compare evidence</button>
    <button class="button ${evaluation ? "primary" : ""}" data-action="experiment-view" data-value="evaluation" aria-pressed="${evaluation}">Offline evaluation</button></div>
    ${evaluation ? `<p>Evaluate the saved v9 input offline to compute fresh EBSR results from the recorded evidence. Use Reports to open previous results.</p>
      ${catalog ? scenarioPanel(catalog.scenarios) : ""}${resultPanel(result)}${result ? exportPanel() : ""}`
      : `${state.experimentCve && catalog && !selected ? empty("Scenario unavailable", "Select a matching experiment from the assessment.") : state.evidence ? evidencePanel(selected) : ""}<section class="card"><h2><svg class="line-icon" aria-hidden="true"><use href="#i-architecture"/></svg> Assessed architecture</h2>${architecture()}</section>`}`;
}

function render() {
  const context = state.context;
  const live = context === "live";
  const historical = context === "historical";
  const savedResult = state.server.results[context];
  const assessment = state.server.assessment;
  const catalog = state.catalogs[context];
  const rows = (live ? assessment?.rows : catalog?.rows) || [];
  const cve = rows.find(row => row.cve_id === state.selected[context + "Cve"]);
  const result = savedResult && (savedResult.scenario_id !== state.selected[context + "Scenario"]
    || (live && savedResult.cve !== cve?.cve_id)) ? null : savedResult;
  const nav = ["live","historical","architecture","experiment"].includes(context) ? "assessments" : context;
  document.querySelectorAll("nav a").forEach(link => {
    if (link.dataset.view === nav) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
  view.innerHTML = context === "home" ? homePage() : context === "reports" ? reportsPage()
    : context === "architecture" ? riskView()
    : context === "experiment" ? experimentPage(catalog, result) : assessmentPage(context, rows, cve, result);
  filteredTable(rows);
  if (context === "reports") reportTable();
}

async function navigate() {
  const [requested, scenario, cve, section] = location.hash.slice(1).split("/");
  if (requested === "page") return;
  const context = requested === "assessments" ? "live" : Object.hasOwn(titles, requested) ? requested : "home";
  state.context = context;
  document.querySelector("#menu-toggle").setAttribute("aria-expanded", "false");
  state.experimentCve = context === "experiment" && section === "evidence" ? decodeURIComponent(cve || "") : null;
  if (context === "experiment" && scenario) {
    state.selected.experimentScenario = decodeURIComponent(scenario);
    state.experimentView = state.experimentCve ? "evidence" : "evaluation";
  }
  if (context === "historical" && scenario && cve) {
    state.selected.historicalScenario = decodeURIComponent(scenario);
    state.selected.historicalCve = decodeURIComponent(cve);
    state.steps.historical = "scenarios";
  }
  if (context === "architecture") {
    state.riskScenario = scenario || state.riskScenario || "EXP2-12546-VULNERABLE-DITTO";
    message("");
    render();
    if (!state.risk && !state.riskLoading) {
      state.riskLoading = true;
      state.riskError = "";
      try {
        const data = await api("/api/architecture-risk", {});
        if (!data.profiles?.control || !data.profiles.vulnerable || !data.evidence?.readback)
          throw new Error("Invalid response. Check the saved v9 bundle and restart RiskScope.");
        state.risk = data;
        riskView();
      } catch (error) {
        state.risk = null;
        state.riskError = error.message;
      } finally {
        state.riskLoading = false;
        if (state.context === context) render();
      }
    }
    if (state.context === context && state.risk && !state.riskExports?.[state.riskScenario]) {
      const id = state.riskScenario;
      if (Object.values(state.risk.profiles).some(group => Object.values(group).some(profile => profile.scenario_id === id))) {
        try {
          const saved = await api("/api/save", {context:"experiment", architecture_scenario:id});
          state.riskExports ||= {};
          state.riskExports[id] = saved.report_id;
          if (state.context === context) render();
        } catch (error) { if (state.context === context) message("Profile evaluated. Report could not be saved: " + error.message, true); }
      }
    }
    return;
  }
  message("");
  render();
  if (context === "live") return;
  if (context === "home" || context === "reports") {
    try {
      const data = await api("/api/reports");
      if (!Array.isArray(data.reports)) throw new Error("Invalid report index response.");
      state.reportIndex = data.reports;
      state.reportIssues = data.issues || [];
      state.reportError = "";
      if (state.context === context) render();
    } catch (error) {
      state.reportIndex = null;
      state.reportError = error.message + " Restart RiskScope with the current application files and retry.";
      if (state.context === context) { render(); if (context === "home") message(state.reportError, true); }
    }
    return;
  }
  if (state.catalogs[context] && (context !== "experiment" || state.evidence)) return;
  message("Loading saved evidence…");
  const requests = [api("/api/" + context)];
  if (context === "experiment") requests.push(api("/api/evidence"));
  const [catalog, evidence] = await Promise.allSettled(requests);
  if (catalog.status === "fulfilled") state.catalogs[context] = catalog.value;
  if (evidence?.status === "fulfilled") {
    state.evidence = evidence.value;
    state.experimentalEvidenceError = "";
  }
  if (state.context === context) {
    const error = [catalog, evidence].find(item => item?.status === "rejected");
    message(error?.reason.message || "", Boolean(error));
    render();
  }
}

let timer;
async function sync() {
  const update = await api("/api/session");
  const changed = JSON.stringify(update.job) !== JSON.stringify(state.server.job);
  state.server = update;
  const live = update.live_analysis;
  if (live && update.assessment && live.cve === state.selected.liveCve
      && live.captured_at === update.assessment.captured_at) {
    state.analysis = {key: coverageKey(live.cve), ...live};
    if (live.report) state.reports.live = live.report;
    if (live.result) {
      state.server.results.live = live.result;
      state.selected.liveScenario = live.result.scenario_id;
    }
  }
  if (changed) render();
  if (update.job?.state === "running") {
    clearTimeout(timer);
    timer = setTimeout(() => sync().catch(error => message(error.message, true)), 550);
  }
}

view.addEventListener("click", async event => {
  const element = event.target.closest("[data-action]");
  if (!element) return;
  const action = element.dataset.action;
  const value = element.dataset.value;
  const context = state.context;
  if (action === "start-assessment") {
    event.preventDefault();
    location.hash = "#assessments";
    state.steps.live = "deployments";
    if (state.server.job?.state === "running" || state.busy) return;
    state.busy = true;
    try { await api("/api/discovery", {}); await sync(); }
    catch (error) { message(error.message,true); }
    finally { state.busy=false; render(); }
    return;
  }
  if (action === "retry-analysis") { await analyzeSelected(state.selected.liveCve); return; }
  if (action === "confirm-route") {
    const routes = state.analysis?.result?.routes || state.analysis?.routes;
    const ids = routes?.[Number(document.querySelector("#live-route").value)];
    if (ids) await analyzeSelected(state.selected.liveCve, ids, document.querySelector("#route-assertion").value || null,document.querySelector("#route-reference").value.trim());
    return;
  }
  if (action === "refresh-analysis") {
    const assessment = state.server.assessment;
    const discovery = state.server.discovery;
    if (!assessment || !discovery || !state.selected.liveCve) {
      message("Run a live assessment before refreshing its evidence.", true);
      return;
    }
    if (state.busy || state.server.job?.state === "running") return;
    state.busy = true;
    message("Refreshing read-only deployment evidence...");
    try {
      await api("/api/refresh-architecture", {
        deployment_id: assessment.deployment.deployment_id,
        captured_at: assessment.captured_at,
        discovery_captured_at: discovery.captured_at,
        cve: state.selected.liveCve,
        route: state.analysis?.result?.route || null,
      });
      await sync();
    } catch (error) {
      message(error.message, true);
    } finally {
      state.busy = false;
      render();
    }
    return;
  }
  if (action === "route-node") { state.selected.routeNode = value; render(); return; }
  if (action === "risk-retry") { state.riskError = ""; navigate(); return; }
  if (action === "retry-reports") { navigate(); return; }
  if (action === "step" || action === "experiment-view") {
    if (action === "step") {
      state.steps[context] = value;
      if (value === "review" && (state.server.assessment && context === "live" || state.server.results[context])) {
        const cve = state.selected[context + "Cve"];
        try {
          const saved = await api("/api/save", {context, cve});
          if (cve === state.selected[context + "Cve"]) state.reports[context] = saved;
        } catch (error) { message(error.message, true); }
      }
    }
    else state.experimentView = value;
    render();
    return;
  }
  if (action === "deployment" || action === "cve") {
    if (action === "cve" && state.selected[context + "Cve"] !== value) delete state.reports[context];
    state.selected[action === "deployment" ? "liveDeployment" : context + "Cve"] = value;
    if (action === "deployment") {
      delete state.selected.routeNode;
      state.steps.live = "vulnerabilities";
      if (state.server.assessment?.deployment.deployment_id !== value) {
        delete state.selected.liveCve;
        delete state.reports.live;
        state.coverage = null;
      }
    }
    if (action === "cve") state.steps[context] = "scenarios";
    render();
    if (action === "cve") document.querySelector(".finding-intro")?.scrollIntoView({block:"start"});
    if (action === "deployment") {
      if (state.busy || state.server.job?.state === "running") return;
      state.busy=true;
      try {
        await api("/api/assessment", {deployment_id:value});
        delete state.selected.liveCve;
        delete state.reports.live;
        await sync();
      } catch (error) { message(error.message,true); }
      finally { state.busy=false; render(); }
    }
    if (action === "cve" && context === "live") {
      loadCoverage(value);
      await analyzeSelected(value);
    }
    return;
  }
  if (action === "retry-coverage") {
    loadCoverage(state.selected.liveCve);
    render();
    return;
  }
  if (state.busy) return;
  state.busy = true;
  message("");
  if (action === "evaluate") message("Evaluating saved evidence…");
  render();
  try {
    if (action === "risk-save") {
      const id = state.riskScenario;
      const saved = await api("/api/save", {context:"experiment", architecture_scenario:id});
      state.riskExports ||= {};
      state.riskExports[id] = saved.report_id;
      message("Saved experimental target profile.");
    } else if (action === "discover") {
      await api("/api/discovery", {});
      await sync();
    } else if (action === "assess") {
      await api("/api/assessment", {deployment_id: state.selected.liveDeployment});
      delete state.selected.liveCve;
      delete state.reports.live;
      await sync();
    } else if (action === "evaluate") {
      state.server.results[context] = await api("/api/evaluate", {
        context, scenario_id: state.selected[context + "Scenario"], cve: state.selected[context + "Cve"],
      });
      state.reports[context] = await api("/api/save", {context, cve: state.selected[context + "Cve"]});
      message("Scenario evaluated and report saved.");
      if (context === "live" || context === "historical") state.steps[context] = "review";
    } else if (action === "save") {
      state.reports[context] = await api("/api/save", {context, cve: state.selected[context + "Cve"]});
      message("Report saved. Downloads are available below.");
    }
  } catch (error) {
    message(error.message, true);
  } finally {
    state.busy = false;
    render();
    if (action === "evaluate") document.querySelector("#results")?.scrollIntoView({block:"start"});
  }
});

function filter(event) {
  const id = event.target.id;
  if (id === "include-archives") { state.includeArchives = event.target.checked; reportTable(); return; }
  if (id === "scenario") {
    state.selected[state.context + "Scenario"] = event.target.value;
    render();
  } else if (["query", "applicability", "severity", "cvsort"].includes(id)) {
    state.filters[state.context][id] = event.target.value;
    filteredTable(state.context === "live" ? state.server.assessment.rows : state.catalogs.historical.rows);
  } else if (id === "report-query" || id === "report-scope") {
    state[id === "report-query" ? "reportQuery" : "reportScope"] = event.target.value;
    reportTable();
  }
}
view.addEventListener("input", filter);
view.addEventListener("change", filter);
const menu = document.querySelector("#menu-toggle");
menu.addEventListener("click", () => menu.setAttribute("aria-expanded", String(menu.getAttribute("aria-expanded") !== "true")));
window.addEventListener("keydown", event => {
  if (event.key === "Escape" && menu.getAttribute("aria-expanded") === "true") {
    menu.setAttribute("aria-expanded", "false");
    menu.focus();
  }
});
window.addEventListener("hashchange", navigate);
sync().then(navigate).catch(error => message(error.message, true));
