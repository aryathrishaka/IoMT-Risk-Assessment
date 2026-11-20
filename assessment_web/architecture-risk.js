"use strict";

const riskTargets = {mosquitto: "Mosquitto", eclipse_ditto: "Eclipse Ditto", influxdb: "InfluxDB"};
const riskFields = {
  mosquitto: "delivery_counts.stale_original_marker, delivery_counts.replacement_marker, deployment.configuration",
  eclipse_ditto: "normal.thing_before.attributes.temperature, retained.downstream_observation.thing_after.attributes.temperature, retained.revocation.enforced, assessment.malicious_thing_changed",
  influxdb: "row_count, rows[].time, rows[].value, rows[].thing_id, rows[].run_marker"
};

function riskReading(target, broker, flow) {
  if (target === "mosquitto") return broker.counts.stale_original_marker > 0
    ? "Retained delivery after revocation observed." : "Tested retained command withheld upstream.";
  if (target === "eclipse_ditto") return flow.thing_changed
    ? `Isolated Thing: baseline ${Number.isInteger(flow.initial_temperature) ? flow.initial_temperature.toFixed(1) : flow.initial_temperature} to retained value ${flow.retained_temperature}.`
    : "No corresponding Thing change in the observation window.";
  return flow.records ? `${flow.records} matching retained-marker records confirmed.`
    : "No matching retained-marker rows in the verified query window.";
}

function riskInterval(interval) {
  return "[" + interval.map(n => String(Number(n.toFixed(4)))).join(", ") + "]";
}

function riskView() {
  const header = '<div class="hero"><div><h1>Architecture-aware risk assessment</h1><p>See how a vulnerability’s effects can cross connected components, and what the available evidence establishes.</p></div></div>';
  if (!state.risk) return header + (state.riskError
    ? `<section class="card" role="alert"><h2>Saved assessment unavailable</h2><p>${escape(state.riskError)}</p>${button("Retry saved assessment", "risk-retry")}</section>`
    : '<p role="status">Evaluating the saved v9 experimental evidence…</p>');
  const {profiles, evidence, cve, version, provenance} = state.risk;
  const [brokerRun, downstream] = evidence.runs;
  const {vulnerable, control} = downstream.arms;
  const selected = Object.entries(profiles).flatMap(([arm, group]) =>
    Object.entries(group).map(([target, profile]) => ({arm, target, profile})))
    .find(entry => entry.profile.scenario_id === state.riskScenario);
  if (!selected) return header + empty("Scenario unavailable", "Choose Architecture Risk in the navigation to open the saved experimental path.");
  const {arm, target, profile} = selected;
  const path = profile.paths[0];
  const flow = downstream.arms[arm];
  const confirmed = evidence.readback.status === "CONFIRMED" && vulnerable.revocation_enforced === true &&
    vulnerable.thing_changed === true && vulnerable.writer_event === true && vulnerable.records > 0 &&
    brokerRun.arms.vulnerable.counts.stale_original_marker > 0 && brokerRun.arms.control.counts.stale_original_marker === 0 &&
    control.source_check === "true" && control.thing_changed === false && control.records === 0 &&
    control.normal_verified === true && control.post_control_verified === true;
  const interval = profile.feasibility_envelope;
  const impacts = path.target_impact;
  const last = path.transitions.at(-1);
  const gap = target === "influxdb" && flow.records > 0 && !last.cve_ids.length &&
    ["A","G"].every(k => last.conditions[k].status === "U") && interval[0] === 0;
  const grades = profile.reproduction_scope.map(r => readable(r.source_observation_grade));
  const fieldPath = target === "influxdb" ? arm + "_retained_marker" : "arms." + arm;
  const source = target === "influxdb" ? evidence.readback.source : target === "mosquitto" ? brokerRun.source : downstream.source;
  const link = target === "influxdb" ? "readback" : target === "mosquitto" ? "run1" : "run2";
  const related = "#experiment/" + encodeURIComponent(profile.scenario_id) + "/" + cve + "/evidence";
  return header + `${state.server.assessment ? '<p><a href="#assessments">← Return to live assessment</a></p>' : ""}<div class="risk-meta"><strong>Saved experimental evidence</strong><span>${escape(cve)} · v9</span><span>${escape(brokerRun.window.start.slice(0,10))} UTC</span></div>
    ${confirmed ? '<p class="risk-conclusion">In the vulnerable configuration, a retained command was delivered after publisher access was revoked. Ditto processed it, and matching telemetry was stored in InfluxDB. The configured control withheld the command while authorized traffic continued to work.</p>' : ""}
    <section class="card risk-map"><h2>Tested experimental path</h2><p>The laboratory publisher represents the IoMT device. Select a component to see its finding.</p>
    ${Object.entries(profiles).map(([name, group]) => `<div class="risk-lane"><div class="lane-label"><strong>${name === "control" ? "Control" : "Vulnerable"}</strong><small>Mosquitto ${escape(downstream.arms[name].version)}</small>${downstream.arms[name].source_check ? `<small>check_retain_source=${escape(downstream.arms[name].source_check)}</small>` : ""}</div>
      ${Object.entries(riskTargets).map(([key, title]) => {
        const p = group[key], obs = downstream.arms[name], broker = brokerRun.arms[name];
        const seen = key === "mosquitto" ? broker.counts.stale_original_marker > 0 : key === "influxdb" ? obs.records > 0 : obs.thing_changed;
        return `<a class="risk-node" aria-current="${p === profile ? "true" : "false"}" href="#architecture/${encodeURIComponent(p.scenario_id)}">
          <strong><svg class="line-icon" aria-hidden="true"><use href="#i-architecture"/></svg>${title}</strong>
          <small>${seen ? "Observed propagation" : key === "mosquitto" ? "Withheld upstream" : "Receiver behaviour unknown"}</small>
          <span>${escape(riskReading(key,broker,obs))}</span>
          </a>`;
      }).join("")}</div>`).join("")}</section>
    <section class="card risk-profile"><h2>${arm === "control" ? "Control" : "Vulnerable"} · ${riskTargets[target]}</h2><p>${escape(riskReading(target,brokerRun.arms[arm],flow))}</p>
      ${impacts.I.status === "UNQUANTIFIED" ? "<p>Integrity consequence observed; magnitude not quantified.</p>" : ""}
      ${gap ? "<p>Database delivery was confirmed. The model cannot fully establish the conditions for the final connection.</p>" : ""}
      ${arm === "control" && target !== "mosquitto" ? "<p>The marker was withheld upstream. Its absence at this target is scoped to the tested event and window. Receiver processing remains unresolved.</p>" : ""}
      <p><strong>Next step.</strong> Verify retained-message authorization on the deployment being assessed, then validate the intended receiver and storage behaviour with an authorized test marker.</p>
      <div class="report-links"><a class="button" href="${related}">Open experiment evidence</a>${!state.riskExports?.[profile.scenario_id] ? button("Prepare report","risk-save",state.busy ? "disabled" : "") : ""}
      ${state.riskExports?.[profile.scenario_id] ? ["html","json"].map(ext=>`<a href="/reports/${escape(state.riskExports[profile.scenario_id])}.${ext}">Download ${ext.toUpperCase()}</a>`).join("") : ""}</div></section>
    <p class="scope-caption">Healthcare Monitoring is downstream context outside experimental validation. Clinical effects remain unverified.</p>
    <details class="card"><summary>Advanced Technical Details</summary><p>${escape(profile.scenario_id)}</p>      <div class="risk-metrics"><div><small>Feasibility interval</small><strong>${riskInterval(interval)}</strong></div>
      ${Object.entries({C:"Confidentiality",I:"Integrity",A:"Availability"}).map(([key,title]) =>
        `<div><small>${title}</small><strong>${escape(({U:"Unknown",F:"Absent in tested window",UNQUANTIFIED:"Unquantified"})[impacts[key].status] || readable(impacts[key].status))}</strong></div>`).join("")}</div>
      <p>Feasibility is a conditional model interval, not an attack probability.</p>
      <p>Source evidence: ${escape(grades.join(", "))}. ${escape(profile.reproduction_scope.map(r=>readable(r.downstream_cve_specific_testing)).join(", "))}.</p>
      ${gap ? "<p>A and G are undefined on the CVE-free Ditto → InfluxDB transition, leaving its lower bound at zero.</p>" : ""}
      <details><summary>Exact model values</summary>${facts([["Feasibility",JSON.stringify(interval)],...Object.entries(impacts).map(([k,v])=>[k,v.status+" · "+JSON.stringify(v.interval)])])}</details>

    <details><summary>What happened</summary><p>${escape(riskReading(target,brokerRun.arms[arm],flow))}</p>${facts([["Broker experiment window (UTC)",windows([brokerRun.window])],["Downstream experiment window (UTC)",windows([downstream.window])],["Normal traffic verified",flow.normal_verified],["Authorized post-control verified",flow.post_control_verified]])}</details>
    <details><summary>Evidence supporting each connection</summary>${path.transitions.map(step=>`<h3>${escape(step.source_product)} → ${escape(step.target_product)}</h3>${conditionEvidence(step.conditions.B)}${conditionEvidence(step.conditions.K)}`).join("")}</details>
    <details><summary>EBSR conditions A/G/H/B/K/Y</summary>${path.transitions.map(step=>`<h3>${escape(step.source)} → ${escape(step.target)}</h3>${Object.entries(step.conditions).map(([k,v])=>`<details><summary>${k} · ${escape(v.meaning)} · ${escape(v.status)} (${escape(labels[v.status])})</summary>${conditionEvidence(v)}</details>`).join("")}`).join("")}</details>
    <details><summary>Unknowns and limitations</summary><p>Unknown channels lack sufficient evidence. Unquantified integrity has no measured numerical magnitude. Duplicate telemetry has no established cause. Each finding applies to its own temporary deployment and observation window.</p></details>
    <details><summary>Raw evidence and provenance</summary>${facts([["Bundle",provenance.path],["Bundle SHA-256",provenance.sha256],["Assessment version",version],["Target deployment",profile.target_component],["Evidence fields",fieldPath+" → "+riskFields[target]],["Evidence file",source.path],["SHA-256",source.sha256],["Run marker",target==="mosquitto"?brokerRun.arms[arm].marker:flow.marker]])}
    <a href="/evidence-source/${link}.json" target="_blank" rel="noopener">Open source fields</a><p>Traffic controls: experiment 2, arms.${arm}.normal.verified and assessment.post_revocation_control_verified. Database counts use the verified readback.</p></details>
    <details><summary>Full architectural context</summary><p>IoMT Device → Mosquitto → Eclipse Ditto → InfluxDB → Healthcare Monitoring</p><p>The laboratory publisher represents the device. Healthcare Monitoring is downstream context outside experimental validation.</p></details></details>`;
}
