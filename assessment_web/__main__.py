"""Local HTTP entry point. Run with python -m assessment_web."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import hashlib
import os
import tempfile
import logging
from pathlib import Path
import re
import socket
from threading import Lock, RLock
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

from . import archives, live_scenarios, service

STATIC = Path(__file__).resolve().parent
REPORTS = service.ROOT / "output/web_assessments"
STATIC_FILES = {"/architecture-risk.js": ("architecture-risk.js", "text/javascript"), "/favicon.ico": ("brand.svg", "image/svg+xml"), "/brand.svg": ("brand.svg", "image/svg+xml"), "/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"),
                "/style.css": ("style.css", "text/css")}
CONTEXTS = {"historical", "experiment"}
SCOPE_LABELS = {"live": "Live deployment", "historical": "Saved historical evidence",
                "experiment": "Recorded experimental configuration"}


class Session:
    def __init__(self):
        self.lock = RLock()
        self.job = None
        self.discovery = None
        self.assessment = None
        self.live_analysis = None
        self.results = {}
        self.architecture_profiles = {}


def assessment_report(session, context, cve=None, architecture_scenario=None):
    if context not in CONTEXTS | {"live"}:
        raise service.AssessmentError("Choose a valid assessment context.")
    with session.lock:
        baseline = session.assessment if context == "live" else None
        result = session.results.get(context)
        if architecture_scenario is not None:
            if context != "experiment" or architecture_scenario not in session.architecture_profiles:
                raise service.AssessmentError("Evaluate this saved experimental profile before exporting.")
            result = session.architecture_profiles[architecture_scenario]
        discovery = session.discovery
    if not baseline and not result:
        raise service.AssessmentError("Complete an assessment before saving a report.")
    if baseline:
        if cve is not None:
            service.selected_cve(baseline, cve)
        if not result or (cve is not None and result["cve"] != cve):
            coverage = service.coverage(baseline, discovery, cve)[0] if cve else None
            result = {
                "context": "live", "status": "NOT_ASSESSED", "cve": cve,
                "deployment_id": baseline["deployment"]["deployment_id"],
                "reason": service.APPLICABILITY_EXPLANATION if coverage and not coverage["compatible"]
                          else "No architecture-aware scenario was evaluated for this report.",
                "coverage": coverage["coverage"] if coverage else "not_selected",
                "evidence_errors": coverage["errors"] if coverage else [],
                "missing_evidence": coverage["missing"] if coverage else [],
            }
    return {
        "report_id": uuid4().hex, "saved_at_utc": service.now(), "context": context,
        "vulnerability_assessment": baseline, "scenario_evaluation": result,
    }


_save_lock = Lock()


def persist(report):
    # Reopening an identical offline result changes only its evaluation timestamp.
    payload = {key: report[key] for key in ("context", "vulnerability_assessment", "scenario_evaluation")}
    if report["context"] != "live" or (payload["scenario_evaluation"] or {}).get("snapshot"):
        payload["scenario_evaluation"] = {k: v for k, v in payload["scenario_evaluation"].items()
                                          if k != "captured_at"}
    identifier = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:32]
    report["report_id"] = identifier
    with _save_lock:
        REPORTS.mkdir(parents=True, exist_ok=True)
        target = REPORTS / (identifier + ".json")
        if target.exists():
            report = read_report(target)
            if report is None:
                raise service.AssessmentError("The existing report is unreadable. Check the saved file before retrying.")
        else:
            stream = tempfile.NamedTemporaryFile(dir=REPORTS, delete=False, suffix=".tmp", mode="w", encoding="utf-8")
            try:
                with stream:
                    json.dump(report, stream, ensure_ascii=False, indent=2)
                os.replace(stream.name, target)
            finally:
                Path(stream.name).unlink(missing_ok=True)
    return {"report_id": identifier, "saved_at_utc": report["saved_at_utc"]}


def report_summary(report):
    context = report["context"]
    baseline = report.get("vulnerability_assessment") or {}
    scenario = report.get("scenario_evaluation") or {}
    deployment = baseline.get("deployment") or {}
    sources = scenario.get("source_deployments") or []
    if not sources:
        sources = [{"product": step["source_product"], "deployment_id": step["source"]}
                   for path in scenario.get("paths", []) for step in path["transitions"]
                   if step.get("cve_ids")]
    product = deployment.get("product") or ", ".join(dict.fromkeys(
        source.get("product") or source["component_id"] for source in sources
    ))
    version = deployment.get("version") or ", ".join(dict.fromkeys(
        source["version"] for source in sources if source.get("version")
    ))
    raw_status = scenario.get("status") or "NOT_ASSESSED"
    display_status = ("COMPONENT-BOUNDED ASSESSMENT — INCOMPLETE EVIDENCE"
                      if scenario.get("bounded_context") else raw_status)
    return {
        "report_id": report["report_id"], "saved_at_utc": report["saved_at_utc"],
        "context": context, "scope": SCOPE_LABELS[context],
        "captured_at": baseline.get("captured_at") or scenario.get("captured_at"),
        "title": scenario.get("description") or
                 f"{product or 'Deployment'} {version} · {scenario.get('cve') or 'Vulnerability scan'}",
        "product": product or "Unrecorded", "version": version or "Unrecorded",
        "deployment_id": deployment.get("deployment_id") or scenario.get("deployment_id"),
        "cve": scenario.get("cve"),
        "assessment_type": ("Component-bounded assessment" if scenario.get("bounded_context") else
                            "Vulnerability scan" if not scenario.get("paths") else
                            "Saved experimental evaluation" if context == "experiment" else "Architecture evaluation"),
        "status": raw_status,
        "display_status": display_status,
        "retrieval": baseline.get("retrieval", {}).get("status"),
    }


def read_report(file):
    try:
        if not file.resolve().is_relative_to(REPORTS.resolve()):
            return None
        report = json.loads(file.read_text(encoding="utf-8"))
        if (report["report_id"] != file.stem or report["context"] not in SCOPE_LABELS
                or not isinstance(report["saved_at_utc"], str)):
            return None
        if not report.get("vulnerability_assessment") and not report.get("scenario_evaluation"):
            return None
        report_summary(report)
        return report
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return None


def report_index():
    items = []
    issues = []
    for file in REPORTS.glob("*.json"):
        if re.fullmatch(r"[0-9a-f]{32}", file.stem) and (report := read_report(file)):
            items.append(report_summary(report))
        else:
            issues.append(f"{file.name}: invalid web assessment. Check the report format.")
    for source in archives.sources(REPORTS.parent):
        try:
            entry = archives.load(source)["summary"]
            canonical = entry["context"] == "experiment" and entry["title"] == "EBSR research-cve-2018-12546-experiment-v9 (evaluated)"
            items.append({**entry, "archived": not canonical})
        except (ValueError, OSError, TypeError, AttributeError, KeyError):
            issues.append(f"{source[2]}: unreadable or unsupported saved assessment.")
    result = {"reports": sorted(items, key=lambda item: item["saved_at_utc"], reverse=True)}
    if issues:
        result["issues"] = issues
    return result


def render_report(report):
    def h(value):
        return escape(str(value if value is not None else "Unrecorded"))

    def pairs(mapping):
        return "".join(f"<dt>{h(key)}</dt><dd>{h(value)}</dd>" for key, value in mapping.items())

    baseline = report["vulnerability_assessment"]
    risk = report["scenario_evaluation"]
    sections = []
    if baseline:
        sections.append("<h2>Vulnerability assessment</h2><dl>" + pairs({
            "Product": baseline["deployment"]["product"], "Version": baseline["deployment"]["version"],
            "Deployment": baseline["deployment"]["deployment_id"], "Captured UTC": baseline["captured_at"],
            **baseline["retrieval"], **baseline["provenance"],
        }) + "</dl><table><thead><tr><th>CVE</th><th>Applicability</th><th>Severity</th>"
            "<th>CVSS version / score</th><th>Reason</th></tr></thead><tbody>")
        for row in baseline["rows"]:
            cvss = (row.get("cvss") or {}).get("primary") or {}
            values = [row["cve_id"], row["status"], cvss.get("severity"),
                      f"{cvss.get('version', '—')} / {cvss.get('score', '—')}", row.get("reason")]
            sections.append("<tr>" + "".join(f"<td>{h(value)}</td>" for value in values) + "</tr>")
        sections.append("</tbody></table>")
    if risk:
        bounded = risk.get("bounded_context") or {}
        sections.append("<h2>Architecture-aware evaluation</h2><dl>" + pairs({
            "Scenario": risk.get("scenario_id"), "Raw engine status": risk["status"],
            "CVE": risk.get("cve"), "Deployment": risk.get("deployment_id"),
            "Assessment state": risk.get("assessment_state"),
            "Architecture position": (bounded.get("architecture_position") or {}).get("label"),
            "Feasibility bounds": (risk.get("feasibility_envelope") if risk.get("feasibility_envelope") is not None
                                   else "Not calculated" if bounded else None),
            **risk.get("provenance", {}),
        }) + "</dl>")
        if risk.get("reason"):
            sections.append(f"<p>{h(risk['reason'])}</p>")
        for entry in risk.get("missing_evidence", []):
            sections.append(f"<p>{h(entry)}</p>")
        for entry in risk.get("evidence_errors", []):
            sections.append(f"<p>{h(entry['context'])} evidence · {h(entry['message'])}</p>")
        if bounded:
            sections.append("<h3>Component-bounded evidence</h3><dl>" + pairs({
                "Architecture position": bounded["architecture_position"]["label"],
                "Known facts": " ".join(bounded.get("known_facts", [])),
                "Potential consequence categories": ", ".join(
                    bounded.get("potential_consequence_categories", {}).get("categories", [])) or "Unresolved",
                "CVE-specific evidence": "; ".join(
                    f"{key}: {value.get('status')}" for key, value in
                    bounded.get("cve_specific_evidence", {}).items()),
                "Numerical assessment": bounded["numerical_assessment"]["status"],
            }) + "</dl><p>" + h(bounded["numerical_assessment"]["reason"]) + "</p>")
            for relation in bounded.get("relationships", []):
                sections.append(f"<p><strong>{h(relation['source_product'])} to {h(relation['target_product'])}</strong> · "
                                f"{h(relation['verification'])} · {h(relation['verification_reason'])}</p>")
            sections.append("<h3>Recommended evidence collection</h3><ol>" + "".join(
                f"<li><strong>{h(action['label'])}</strong> · {h(action['detail'])}</li>"
                for action in bounded.get("recommended_actions", [])) + "</ol>")
            sections.append("<details><summary>Component context provenance</summary><pre>" +
                            h(json.dumps(bounded.get("provenance", {}), ensure_ascii=False, indent=2)) +
                            "</pre></details>")
        for path in risk.get("paths", []):
            sections.append(f"<h3>{h(path['path_id'])}</h3><dl>" + pairs({
                "Path feasibility": path["feasibility"]["interval"],
                **{f"Target {channel}": f"{item['status']} · {item['interval']}"
                   for channel, item in path["target_impact"].items()},
            }) + "</dl>")
            for step in path["transitions"]:
                sections.append(f"<h4>{h(step['source'])} to {h(step['target'])}</h4><dl>")
                for variable, item in step["conditions"].items():
                    text = item["reason"] + [
                        line for source in item["sources"] for line in source["evidence"]
                    ]
                    sections.append(pairs({f"{variable} · {item['meaning']}": f"{item['status']} · {' '.join(text)}"}))
                sections.append("</dl>")
    summary = report_summary(report)
    paths = (risk or {}).get("paths", [])
    scope = summary["scope"]
    rows = (baseline or {}).get("rows", [])
    selected = (risk or {}).get("cve")
    relevant = [r for r in rows if r["cve_id"] == selected or r["status"] == "AFFECTED"]
    if paths:
        finding = risk.get("description") or "Scenario evaluated within its recorded scope."
        if risk.get("component_level"):
            finding += (" Component-level evaluation only. CVE capability, controls and target C/I/A remain "
                        "UNKNOWN unless supported by separate evidence; no downstream component is inferred.")
        elif risk.get("snapshot"):
            finding += " This candidate route has no observed vulnerability propagation. Conditional feasibility: " + (str(risk["feasibility_envelope"]) if risk["feasibility_envelope"] else "unquantified with available inputs")
        channels = [p["target_impact"]["I"]["status"] for p in paths]
        if "UNQUANTIFIED" in channels:
            finding += " An integrity consequence was observed. Its magnitude was not measured."
    else:
        bounded = (risk or {}).get("bounded_context") or {}
        if bounded:
            finding = ("Component-bounded assessment. Applicability and CVE-specific consequences remain separate "
                       "from architecture connectivity. " + " ".join(bounded.get("known_facts", [])))
        else:
            finding = "Downstream effects remain unassessed for this deployment. Applicability alone does not establish propagation."
    evidence = []
    for path in paths:
        for item in path["target_evidence"].values():
            for source in item["sources"]:
                evidence.extend(source["evidence"])
    observed = ""
    if report["context"] == "experiment":
        source_findings = [r.get("source_observation_label", "") for r in risk.get("reproduction_scope", [])]
        observed = " ".join(dict.fromkeys(filter(None, source_findings + evidence)))
    cves = list(dict.fromkeys(r["cve_id"] for r in (risk or {}).get("reproduction_scope", [])))
    limits = ((risk or {}).get("bounded_context") or {}).get("missing_evidence") or \
             (risk or {}).get("missing_evidence") or ["Findings apply only to the recorded configuration, target and observation window."]
    guidance = ("Verify retained-message authorization after access changes and confirm that authorized traffic still works."
                if "CVE-2018-12546" in cves or selected == "CVE-2018-12546" else
                "Review applicable vendor advisories, verify the deployment configuration and collect evidence for the affected route.")
    evidence_guidance = (risk or {}).get("evidence_guidance")
    if evidence_guidance:
        next_action = evidence_guidance.get("next_action") or {}
        guidance = ((next_action.get("label") or "Collect additional evidence") + ". " +
                    (next_action.get("detail") or "")).strip()
        limits.extend(evidence_guidance.get("unknown", []))
    components = f"{h(summary['product'])} {h(summary['version'])}"
    if paths:
        target_names = {"mosquitto":"Mosquitto", "eclipse_ditto":"Eclipse Ditto", "influxdb":"InfluxDB"}
        targets = [p["transitions"][-1]["target_product"] for p in paths if p.get("transitions")]
        components += " · Target: " + h(", ".join(dict.fromkeys(target_names.get(t, t) for t in targets)))
    if baseline:
        components += f" · {h(baseline['deployment']['deployment_id'])}. Retrieval: {h(summary['retrieval'])}."
        components += f" {len(rows)} candidates; {sum(r['status']=='AFFECTED' for r in rows)} affected; {sum(r['status']=='UNKNOWN' for r in rows)} unknown."
    vuln_list = ", ".join(r["cve_id"] for r in relevant[:8]) or ", ".join(cves)
    if selected and baseline:
        selected_row = next((r for r in rows if r["cve_id"] == selected), {})
        metric = (selected_row.get("cvss") or {}).get("primary") or {}
        vuln_list = f"{selected} · {selected_row.get('status', 'Unrecorded')} · severity {metric.get('severity', 'unrecorded')}"
    if (risk or {}).get("snapshot"):
        limits = ["Active validation required to establish vulnerability propagation. CVE-specific receiver behaviour and target consequences remain unverified."]
        relationship_labels = {
            "VERIFIED_CONFIGURATION": "Configuration verified",
            "OBSERVED_COMMUNICATION": "Communication observed",
            "NETWORK_ONLY": "Shared network only",
            "NOT_CONFIGURED": "No matching application configuration",
            "UNKNOWN": "Unknown",
        }
        for edge in risk["snapshot"]["connections"]:
            label = relationship_labels.get(edge.get("verification"), edge.get("verification", "unknown")).replace("_", " ")
            finding += (f" {edge.get('source_product',edge['source'])} to {edge.get('target_product',edge['target'])}: "
                        f"{label}. {edge.get('verification_reason', edge['basis'])} "
                        "Vulnerability propagation remains not verified.")
        snapshot = risk["snapshot"]
        limits.extend(snapshot.get("prerequisite_findings", []))
        sections.append("<h3>Deployment inspections and connection evidence</h3><pre>" +
                        h(json.dumps(snapshot, ensure_ascii=False, indent=2)) + "</pre>")
    overview = [
        ("Assessment overview", f"{scope} · {summary.get('display_status', summary['status'])}" +
         (f" · {risk.get('assessment_state')}" if (risk or {}).get("assessment_state") else "")),
        ("Components and vulnerabilities", None),
        ("Architecture-level risk findings", finding),
        ("Observed experimental evidence", observed or "No experimental observation is attached to this assessment."),
        ("Unknowns and limitations", " ".join(limits) + " Healthcare Monitoring lies outside experimental validation."),
        ("Recommended mitigations and validation", guidance),
    ]
    body = "".join("<section><h2>" + h(title) + "</h2><p>" +
                   (h(value) if value is not None else components + "<br>" + h(vuln_list)) + "</p></section>"
                   for title, value in overview)
    if (risk or {}).get("snapshot", {}).get("nodes"):
        snapshot = risk["snapshot"]
        graph = " → ".join(h(node["product"]) for node in snapshot["nodes"])
        graph_caption = "Selected deployment route · relationship evidence is assessed per connection."
        body += "<section><h2>Evidence collected</h2>" + "".join("<p><strong>" + h(node["product"]) +
            "</strong> " + h(node["version"]) + " · " + h(node["deployment_id"]) + " · " +
            h(len(node["inspections"])) + " verified member inspection(s). " + h(" ".join(node["issues"])) +
            "</p>" for node in snapshot["nodes"]) + "</section>"
    else:
        graph = "IoMT Device → Mosquitto → Eclipse Ditto → InfluxDB → Healthcare Monitoring"
        graph_caption = "Reference architecture · laboratory publisher represents the device."
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>RiskScope | Assessment report</title><style>body{font:16px/1.45 system-ui;color:#202338;max-width:58rem;'
            'margin:2rem auto;padding:0 1rem}h1{font-size:1.7rem}h2{font-size:1.1rem;margin:.8rem 0 .2rem;color:#39377a}'
            'p{margin:.2rem 0 .6rem}aside,summary{padding:.75rem;background:#efedfc;border-radius:.45rem}'
            'summary{cursor:pointer}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;'
            'padding:.4rem;text-align:left}dt{font-weight:600}dd{margin:0 0 .5rem}body{overflow-wrap:anywhere}pre{white-space:pre-wrap;font-size:.85rem}</style>'
            f'<header><strong>RiskScope</strong><h1>{h(summary["title"])}</h1><p>{h(report["saved_at_utc"])}</p></header>'
            f'<aside aria-label="Architecture">{graph}<br><small>{graph_caption}</small></aside>' +
            body + '<details><summary>Technical appendix</summary>' + "".join(sections) + '</details></html>')



class AppServer(ThreadingHTTPServer):
    daemon_threads = True

    allow_reuse_address = False

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def __init__(self, address):
        super().__init__(address, Handler)
        self.sessions = {}
        self.sessions_lock = Lock()
        self.workers = ThreadPoolExecutor(max_workers=2)

    def server_close(self):
        super().server_close()
        if hasattr(self, "workers"):
            self.workers.shutdown(wait=False, cancel_futures=True)

    def session(self, session_id):
        with self.sessions_lock:
            return self.sessions.setdefault(session_id, Session())


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def respond(self, status, content, media="application/json", filename=None):
        self.send_response(status)
        self.send_header("Content-Type", media + "; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; "
                         "frame-ancestors 'none'; base-uri 'none'")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(content)

    def json(self, data, status=200):
        self.respond(status, json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def dispatch(self, method):
        url = urlsplit(self.path)
        path = url.path
        host = self.headers.get("Host", "")
        if host not in {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}:
            return self.json({"error": "Use the loopback address printed when the server starts."}, 403)
        if method == "GET" and path in STATIC_FILES:
            name, media = STATIC_FILES[path]
            return self.respond(200, (STATIC / name).read_bytes(), media)

        client = self.headers.get("X-Assessment-Session", "")
        download = re.fullmatch(r"/reports/([0-9a-f]{32})\.(json|html)", path)
        if method == "GET" and download:
            return self.download(*download.groups())
        source = re.fullmatch(r"/evidence-source/(run1|run2|readback)\.json", path)
        if method == "GET" and source:
            try:
                evidence = service.experimental_evidence()
                key = source.group(1)
                return self.json(evidence["readback"] if key == "readback"
                                 else evidence["runs"][int(key[-1]) - 1])
            except (service.AssessmentError, KeyError, TypeError, ValueError):
                return self.json({"error": "The saved source evidence is unavailable or malformed."}, 400)
        if not re.fullmatch(r"[0-9a-f]{32}", client):
            return self.json({"error": "An assessment session is required."}, 403)
        session = self.server.session(client)
        routes = {
            ("GET", "/api/session"): lambda: self.session_state(session),
            ("POST", "/api/discovery"): lambda: self.start(session, "discovery"),
            ("POST", "/api/assessment"): lambda: self.start(session, "assessment", self.body().get("deployment_id")),
            ("GET", "/api/historical"): lambda: service.catalog("historical"),
            ("GET", "/api/experiment"): lambda: service.catalog("experiment"),
            ("GET", "/api/evidence"): service.experimental_evidence,
            ("GET", "/api/reports"): report_index,
            ("GET", "/api/coverage"): lambda: self.coverage(session, parse_qs(url.query).get("cve", [None])[0]),
            ("POST", "/api/architecture-risk"): lambda: self.architecture_risk(session),
            ("POST", "/api/analyze"): lambda: self.analyze(session, self.body()),
            ("POST", "/api/refresh-architecture"): lambda: self.refresh(session, self.body()),
            ("POST", "/api/evaluate"): lambda: self.evaluate(session, self.body()),
            ("POST", "/api/save"): lambda: self.save(session, self.body()),
        }
        operation = routes.get((method, path))
        if operation is None:
            return self.json({"error": "This assessment endpoint does not exist."}, 404)
        try:
            data = operation()
            self.json(data)
        except service.AssessmentError as error:
            self.json({"error": str(error)}, 400)
        except (KeyError, TypeError, AttributeError, IndexError):
            self.json({"error": "The saved evidence or submitted request has an invalid structure."}, 400)
        except Exception as error:
            logging.error("Assessment request failed (%s)", type(error).__name__)
            self.json({"error": "The local application could not complete this request."}, 500)

    def body(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 16_384:
                raise ValueError
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict):
                raise ValueError
            return data
        except ValueError:
            raise service.AssessmentError("Supply a valid JSON request.") from None

    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def session_state(self, session):
        with session.lock:
            return {
                "job": dict(session.job) if session.job else None,
                "discovery": session.discovery, "assessment": session.assessment,
                "live_analysis": session.live_analysis,
                "results": dict(session.results),
                "architecture": service.architecture,
            }

    def start(self, session, kind, deployment_id=None):
        with session.lock:
            if session.job and session.job["state"] == "running":
                raise service.AssessmentError("An assessment operation is already running.")
            deployment = None
            if kind == "assessment":
                if not session.discovery or session.discovery["status"] != "COMPLETE":
                    raise service.AssessmentError("Discover deployments before starting a live assessment.")
                matches = [row for row in session.discovery["supported"]
                           if row["assessable"] and row["deployment_id"] == deployment_id]
                if len(matches) != 1:
                    raise service.AssessmentError("Select a supported, unambiguous deployment with a usable version.")
                deployment = matches[0]
            session.job = {"kind": kind, "state": "running", "message": "Starting " + kind}
            self.server.workers.submit(self.run_job, session, kind, deployment)
        return {"accepted": True}

    @staticmethod
    def run_job(session, kind, deployment):
        def progress(message):
            with session.lock:
                session.job["message"] = message

        try:
            if kind == "discovery":
                progress("Inspecting running Docker deployments")
                result = service.deployments(progress)
                with session.lock:
                    session.discovery = result
                    session.assessment = None
                    session.live_analysis = None
                    session.results.pop("live", None)
            else:
                result = service.assess(deployment, progress)
                with session.lock:
                    session.assessment = result
                    session.live_analysis = None
                    session.results.pop("live", None)
                persist(assessment_report(session, "live"))
            with session.lock:
                session.job.update(state="finished", message="Operation finished")
        except Exception as error:
            logging.error("Assessment operation failed (%s)", type(error).__name__)
            with session.lock:
                session.job.update(state="error", message="Operation failed. Check Docker or NVD availability and retry.")

    @staticmethod
    def coverage(session, cve):
        with session.lock:
            assessment, discovery = session.assessment, session.discovery
        return service.coverage(assessment, discovery, cve)[0]

    def analyze(self, session, request):
        with session.lock:
            if session.job and session.job["state"] == "running":
                raise service.AssessmentError("Wait for discovery or scanning to finish.")
            data = live_scenarios.analyze(session.discovery, session.assessment, request, REPORTS.parent / "live_scenarios")
            self.record_analysis(session, request, data)
            return data

    @staticmethod
    def record_analysis(session, request, data):
        """Store one automatic analysis without creating a second result path."""
        if data["status"] == "EVALUATED":
            result = data["result"]
            previous = session.results.get("live", {})
            if previous.get("provenance") == result["provenance"]:
                data["result"] = previous
            session.results["live"] = data["result"]
            data["report"] = persist(assessment_report(session, "live", request["cve"]))
        elif data["status"] in ("NOT_ASSESSED", "CHOOSE_ROUTE"):
            session.results.pop("live", None)
            report = assessment_report(session, "live", request["cve"])
            report["scenario_evaluation"].update(status=data["status"], reason=data["reason"],
                                                 assessment_state=data.get("assessment_state"))
            bounded = data.get("bounded_context")
            if bounded:
                report["scenario_evaluation"]["bounded_context"] = bounded
                report["scenario_evaluation"]["missing_evidence"] = bounded["missing_evidence"]
            else:
                report["scenario_evaluation"]["missing_evidence"] = [data["reason"]]
            if data.get("guidance"):
                report["scenario_evaluation"]["evidence_guidance"] = data["guidance"]
            session.results["live"] = report["scenario_evaluation"]
            data["report"] = persist(report)
        session.live_analysis = {
            **data, "cve": request["cve"], "captured_at": session.assessment["captured_at"],
            "analyzed_at": service.now(),
        }

    def refresh(self, session, request):
        """Start a read-only refresh of the selected deployment and CVE."""
        with session.lock:
            if session.job and session.job["state"] == "running":
                raise service.AssessmentError("Wait for the current assessment operation to finish.")
            assessment, discovery = session.assessment, session.discovery
            if not assessment or not discovery:
                raise service.AssessmentError("Run a live assessment before refreshing its evidence.")
            deployment = assessment["deployment"]
            if (request.get("deployment_id") != deployment["deployment_id"]
                    or request.get("captured_at") != assessment["captured_at"]
                    or request.get("discovery_captured_at") != discovery["captured_at"]):
                raise service.AssessmentError("The assessment snapshot changed. Review the refreshed evidence before continuing.")
            cve = request.get("cve")
            service.selected_cve(assessment, cve)
            route = request.get("route")
            if route is not None and (not isinstance(route, list) or not route
                                      or len(route) > 8 or any(not isinstance(item, str) for item in route)):
                raise service.AssessmentError("Supply the current deployment route as a list of deployment IDs.")
            pending = {
                "deployment_id": deployment["deployment_id"], "cve": cve,
                "route": list(route) if route is not None else None,
                "assessment_captured_at": assessment["captured_at"],
                "discovery_captured_at": discovery["captured_at"],
            }
            session.job = {
                "kind": "refresh", "state": "running", "message": "Starting read-only evidence refresh",
                "request": pending, "refresh_status": "RUNNING", "requested_at": service.now(),
            }
            self.server.workers.submit(self.run_refresh, session, pending)
        return {"accepted": True}

    def run_refresh(self, session, request):
        """Collect and evaluate fresh passive evidence without altering the lab."""
        def progress(message):
            with session.lock:
                session.job["message"] = message

        try:
            progress("Re-collecting Docker deployments and configuration evidence")
            discovery = service.deployments(progress)
            if discovery.get("status") != "COMPLETE":
                raise service.AssessmentError(
                    "Read-only evidence collection did not complete (" + str(discovery.get("status")) +
                    "). The previous evidence was retained.")
            matches = [row for row in discovery["supported"]
                       if row.get("assessable") and row.get("deployment_id") == request["deployment_id"]]
            if len(matches) != 1:
                raise service.AssessmentError(
                    "The selected deployment identity is absent or ambiguous after refresh. "
                    "The previous evidence was retained.")
            deployment = matches[0]
            with session.lock:
                previous_assessment = session.assessment
                previous_discovery = session.discovery
            if (not previous_assessment
                    or deployment.get("component_id") != previous_assessment["deployment"].get("component_id")):
                raise service.AssessmentError(
                    "The selected deployment now identifies a different component. "
                    "The previous evidence was retained.")
            progress("Rescanning vulnerability applicability and CVSS evidence")
            assessment = service.assess(deployment, progress)
            if (live_scenarios.evidence_signature(previous_discovery, previous_assessment)
                    == live_scenarios.evidence_signature(discovery, assessment)):
                with session.lock:
                    session.job.update(state="finished", refresh_status="UNCHANGED",
                                       message="Evidence refresh completed; no substantive evidence changed.")
                return
            progress("Updating the deployment-scoped EBSR assessment")
            analysis_request = {
                "deployment_id": deployment["deployment_id"], "captured_at": assessment["captured_at"],
                "cve": request["cve"], "route": request["route"],
            }
            data = live_scenarios.analyze(
                discovery, assessment, analysis_request, REPORTS.parent / "live_scenarios",
                require_explicit_route=True)
            with session.lock:
                session.discovery = discovery
                session.assessment = assessment
                session.results.pop("live", None)
                self.record_analysis(session, analysis_request, data)
                session.job.update(
                    state="finished", refresh_status="CHANGED",
                    message=("Evidence refreshed and re-evaluated." if data["status"] == "EVALUATED"
                             else "Evidence refreshed; the current outcome still requires review."),
                    outcome=data["status"], report_id=data.get("report", {}).get("report_id"))
        except service.AssessmentError as error:
            logging.warning("Read-only evidence refresh failed (%s)", type(error).__name__)
            with session.lock:
                session.job.update(state="error", refresh_status="FAILED", message=str(error))
        except Exception as error:
            logging.error("Read-only evidence refresh failed (%s)", type(error).__name__)
            with session.lock:
                session.job.update(
                    state="error", refresh_status="FAILED",
                    message="The evidence refresh failed. The previous evidence was retained.")

    def evaluate(self, session, request):
        context = request.get("context")
        if context == "live":
            with session.lock:
                assessment = session.assessment
                if session.job and session.job["state"] == "running":
                    raise service.AssessmentError("Wait for the live operation to finish.")
                result = service.evaluate_live(assessment, session.discovery, request.get("cve"),
                                               request.get("scenario_id"))
                session.results[context] = result
            persist(assessment_report(session, "live", request.get("cve")))
            return result
        if context not in CONTEXTS:
            raise service.AssessmentError("Choose a saved assessment context.")
        result = service.evaluate(context, request.get("scenario_id"))
        with session.lock:
            session.results[context] = result
        persist(assessment_report(session, context))
        return result

    @staticmethod
    def architecture_risk(session):
        data = service.architecture_assessment()
        with session.lock:
            session.architecture_profiles = {p["scenario_id"]: p for arm in data["profiles"].values()
                                             for p in arm.values()}
        return data

    def save(self, session, request):
        report = assessment_report(session, request.get("context"), request.get("cve"), request.get("architecture_scenario"))
        return persist(report)

    def download(self, report_id, extension):
        report = read_report(REPORTS / f"{report_id}.json")
        if report is None:
            source = next((item for item in archives.sources(REPORTS.parent) if item[0] == report_id), None)
            if source is None:
                return self.json({"error": "Saved report not found."}, 404)
            try:
                report = archives.load(source)
            except (ValueError, OSError, TypeError, AttributeError, KeyError):
                return self.json({"error": "Cannot open this snapshot. Check the source artifact."}, 422)
            summary = report["summary"]
            html = archives.render(report) if extension == "html" else ""
        else:
            html = render_report(report) if extension == "html" else ""
        content = (html if extension == "html" else json.dumps(report, ensure_ascii=False, indent=2)).encode("utf-8")
        self.respond(200, content, "text/html" if extension == "html" else "application/json",
                     None if self.path.endswith("?view=1") and extension == "html"
                     else f"riskscope-{report_id}.{extension}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", default=8765, type=int)
    args = parser.parse_args()
    with AppServer(("127.0.0.1", args.port)) as server:
        print(f"Local assessment interface: http://127.0.0.1:{server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
