"""Safe report projections of saved baseline and EBSR snapshots."""
from html import escape
from functools import lru_cache
from hashlib import sha256
import json


def sources(output):
    root = output.parent
    files = [*root.glob("*baseline*.json"), *output.glob("*baseline*.json"),
             *(output / "ebsr_assessments").glob("ebsr-assessment-*.json")]
    for path in sorted(files):
        if path.stem.endswith(("-comparison", "-reporting-update")) or path.resolve() != path:
            continue
        relative = path.relative_to(root).as_posix()
        yield sha256(relative.encode()).hexdigest()[:32], path, relative


def baseline(row):
    retrieval = row.get("retrieval") or {}
    return {"component": row["component"], "version": row["version"],
            "deployment": row.get("deployment_id"), "candidates": row["candidates"],
            "capture": retrieval.get("recorded_at_utc"), "retrieval": retrieval.get("status"),
            "assessment_performed": row.get("assessment_performed"),
            "not_affected_count": row.get("not_affected_count"),
            "findings": [{key: finding.get(key) for key in ("cve_id", "status", "reason")}
                         for group in ("affected", "affected_other_scale", "unknown", "not_affected")
                         for finding in row.get(group, [])]}


@lru_cache(maxsize=100)
def projection(path, relative, identifier, modified, size):
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    context = "historical"
    if isinstance(data, dict) and "scenario_results" in data:
        inputs = data["adapter_input"]
        if inputs.get("saved_experimental_assessment") or inputs.get("experiment_governance"):
            context = "experiment"
        deployments = inputs["deployments"]
        products = [entry["component_id"] for entry in deployments]
        versions = [str(entry.get("version") or "Unrecorded") for entry in deployments]
        date = data["generated_at"]
        if not isinstance(date, str):
            raise ValueError("Invalid evaluation timestamp")
        title = "EBSR " + str(data["assessment_version"])
        if path.stem.endswith(("-evaluated", "-replayed")):
            title += " (" + path.stem.rsplit("-", 1)[1] + ")"
        detail = [{key: row.get(key) for key in ("scenario_id", "status", "deployment_id",
                   "target_component", "feasibility_envelope", "vulnerability_ids")} for row in data["scenario_results"]]
        for item, row in zip(detail, data["scenario_results"]):
            item["target_impacts"] = [p.get("target_impact") for p in row.get("paths", [])]
        status = "SAVED_EVALUATION"
    else:
        if isinstance(data, dict):
            data = [row for group in data.values() for row in group]
        if not isinstance(data, list) or not data:
            raise ValueError("Empty or unsupported snapshot")
        detail = [baseline(row) for row in data]
        products = [row["component"] for row in detail]
        versions = [str(row["version"]) for row in detail]
        dates = sorted({row["capture"] for row in detail if row["capture"]})
        date = " / ".join(dates)
        title = "Baseline assessment " + ", ".join(dict.fromkeys(products))
        status = " / ".join(dict.fromkeys(row["retrieval"] or "RETRIEVAL_UNRECORDED" for row in detail))
    summary = dict(report_id=identifier, saved_at_utc=date, context=context, title=title,
                   product=", ".join(dict.fromkeys(products)), version=", ".join(dict.fromkeys(versions)),
                   scope="Recorded experiment" if context == "experiment" else "Saved historical assessment",
                   status=status)
    return dict(summary=summary, source=relative, results=detail)


def load(source):
    identifier, path, relative = source
    stat = path.stat()
    return projection(path, relative, identifier, stat.st_mtime_ns, stat.st_size)


def render(report):
    summary = report["summary"]

    def h(value):
        return escape(str(value if value not in (None, "") else "Unrecorded"))

    def table(headers, rows):
        return ("<table><thead><tr>" + "".join(f"<th>{h(key)}</th>" for key in headers)
                + "</tr></thead><tbody>" + "".join("<tr>" + "".join(f"<td>{h(v)}</td>" for v in row)
                + "</tr>" for row in rows) + "</tbody></table>")

    sections = []
    for row in report["results"]:
        if "component" in row:
            sections.append(f"<h2>{h(row['component'])} {h(row['version'])}</h2>"
                            f"<p>Deployment {h(row['deployment'])} | Retrieval {h(row['retrieval'])} | "
                            f"Candidates {h(row['candidates'])}</p>")
            sections.append(table(["CVE", "Applicability", "Reason"], (
                (r["cve_id"], r["status"], r["reason"]) for r in row["findings"])))
        else:
            sections.append(f"<h2>{h(row['scenario_id'])}</h2><p>{h(row['status'])} | "
                            f"Target {h(row['target_component'])}</p>"
                            f"<p>Feasibility interval {h(row['feasibility_envelope'])}</p>")
            sections.append(table(["Path", "Target channel", "Evidence state", "Interval"], (
                (index, channel, impact.get("status"), impact.get("interval"))
                for index, impacts in enumerate(row["target_impacts"], 1)
                for channel, impact in (impacts or {}).items())))
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><title>RiskScope | Saved assessment</title>'
            '<style>body{font:16px system-ui;max-width:64rem;margin:3rem auto;padding:1rem;color:#202338}'
            'td,th{padding:.5rem;text-align:left;border-bottom:1px solid #e2e4ee}p,td{overflow-wrap:anywhere}'
            'table{border-collapse:collapse}</style>'
            f'<p>RiskScope | {h(summary["scope"])}</p><h1>{h(summary["title"])}</h1>'
            f'<p>Capture / evaluation UTC: {h(summary["saved_at_utc"])}</p><p>Source: {h(report["source"])}</p>'
            + "".join(sections) + "</html>")
