"""Assessment services and explicit public projections for the local interface."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from . import passive
from architecture import architecture
from baseline import build_component_baseline
from ebsr_adapter import build_assessment, merge_live_assessment
from nvd_api import search_cves_by_keyword_with_status
from version_detector import detect_versions

ROOT = Path(__file__).resolve().parents[1]
BUNDLES = {
    "historical": "scenarios/ebsr_mosquitto_12546_12550_12551_v7.json",
    "experiment": "scenarios/ebsr_cve_2018_12546_experiment_v9.json",
}
LIVE_BUNDLE = "scenarios/deployment_scoped.json"
APPLICABILITY_EXPLANATION = (
    "Vulnerability applicability has been assessed. Architecture-aware evaluation "
    "requires a scenario and evidence matching this deployment."
)
CONDITIONS = {
    "A": "CVE applicability", "G": "Attacker prerequisites",
    "H": "Deployment prerequisites", "B": "Architecture relationship",
    "K": "CVE-specific transition capability", "Y": "Receiver processing and controls",
}


class AssessmentError(ValueError):
    """An error safe to show to the application user."""


def now():
    return datetime.now(timezone.utc).isoformat()


def pick(record, *keys):
    return {key: record[key] for key in keys if key in record}


def artifact(path):
    relative = path.replace("\\", "/")
    file = (ROOT / relative).resolve()
    if not file.is_relative_to(ROOT):
        raise AssessmentError("The saved artifact path is outside the project.")
    try:
        content = file.read_bytes()
        data = json.loads(content)
        if not isinstance(data, dict):
            raise ValueError
    except (OSError, ValueError):
        raise AssessmentError(f"Saved artifact missing or malformed: {relative}") from None
    return data, {"path": relative, "sha256": hashlib.sha256(content).hexdigest()}


def deployments(progress=None):
    supported, other = [], []
    failure = None
    inventory = detect_versions()
    if progress:
        progress("Inspecting component configurations, endpoints and recent activity")
    for name, row in inventory.items():
        status = row.get("status", "UNKNOWN")
        if status.startswith("DOCKER_") or status == "MALFORMED_OUTPUT":
            failure = status
            continue
        public = {
            **pick(row, "component_id", "deployment_id", "version", "version_source", "nvd_search_term", "container_ids", "architecture_metadata", "image_id", "image_digest"),
            "product": row.get("architecture_component") or row.get("display_name") or name,
            "status": status,
            "runtime": "Listed running" if row.get("container") else "Unverified",
        }
        states = sorted({meta["runtime"] for meta in row.get("architecture_metadata", []) if meta.get("runtime")})
        if states:
            public["runtime"] = ", ".join(states)
        public["assessable"] = bool(
            not row.get("diagnostic") and public.get("deployment_id") and public.get("component_id")
            and public.get("nvd_search_term") and public.get("version") not in (None, "", "latest")
        )
        if public["assessable"]:
            if progress:
                progress("Collecting read-only evidence for " + public["product"])
            public["inspections"] = passive.collect(public)
        (other if row.get("diagnostic") else supported).append(public)
    return {"status": failure or "COMPLETE", "supported": supported, "other": other, "captured_at": now()}


def public_rows(record):
    rows = [
        {**pick(row, "cve_id", "status", "reason", "cvss", "description")}
        for key in ("affected", "affected_other_scale", "unknown", "not_affected")
        for row in record.get(key, [])
    ]
    return rows


def safe_reference(url):
    try:
        parts = urlsplit(url)
        return parts.scheme in ("http", "https") and bool(parts.hostname) and not parts.username
    except (TypeError, ValueError):
        return False


def assess(deployment, progress):
    progress("Retrieving NVD candidates")
    retrieval = search_cves_by_keyword_with_status(deployment["nvd_search_term"], results_per_page=100)
    captured_at = now()
    progress("Checking CPE applicability and selecting CVSS metrics")
    record = build_component_baseline(
        deployment["product"], deployment["version"], retrieval["items"],
        component_id=deployment["component_id"], discovery_evidence=deployment,
        retrieval=pick(retrieval, "status", "received", "total_results"),
        assessment_version_source=deployment.get("version_source"),
    )
    cves = {item["cve"].get("id"): item["cve"] for item in retrieval["items"]
            if isinstance(item, dict) and isinstance(item.get("cve"), dict)}
    rows = public_rows(record)
    for row in rows:
        cve = cves.get(row["cve_id"], {})
        row["description"] = next(
            (value["value"] for value in cve.get("descriptions") or []
             if isinstance(value, dict) and value.get("lang") == "en"
             and isinstance(value.get("value"), str)), row["description"]
        )
        row["references"] = [
            ref["url"] for ref in cve.get("references") or []
            if isinstance(ref, dict) and safe_reference(ref.get("url"))
        ]
    return {
        "context": "live", "captured_at": captured_at, "deployment": deployment,
        "retrieval": record["retrieval"], "rows": rows,
        "provenance": {"source": "NVD CVE API 2.0", "search_term": deployment["nvd_search_term"]},
    }


def scenario_cves(scenario):
    return sorted({
        cve for path in scenario["paths"] for step in path["transitions"]
        for cve in step.get("cve_ids", [])
    } | ({scenario["cve_under_test"]} if scenario.get("cve_under_test") else set()))


def observation_windows(document, scenario):
    identifiers = {
        binding.get("proposition_id")
        for path in scenario["paths"] for step in path["transitions"]
        for binding in step["conditions"].values() if isinstance(binding, dict)
    }
    return list({
        window["start"]: window
        for item in document.get("evidence", []) if item.get("proposition_id") in identifiers
        if (window := item.get("observation_window_utc")) and window.get("start")
    }.values())


def catalog(context, source=None):
    document, provenance = source or artifact(BUNDLES[context])
    historical_date = None
    if context == "historical":
        snapshot, _ = artifact(document["evidence_provenance"]["historical_cve_source"])
        historical_date = snapshot.get("generated_at")
    people = {item["attacker_id"]: item for item in document["attacker_profiles"]}
    by_id = {item["deployment_id"]: item for item in document["deployments"]}
    scenarios = []
    for item in document["scenarios"]:
        steps = [step for path in item["paths"] for step in path["transitions"]]
        origins = {step["source_deployment_id"] for step in steps if step.get("cve_ids")}
        if item.get("cve_under_test"):
            origins.update(path["transitions"][0]["source_deployment_id"] for path in item["paths"])
        subjects = {
            cve: sorted({by_id[step["source_deployment_id"]]["component_id"]
                         for step in steps if cve in step.get("cve_ids", [])}
                        | ({by_id[path["transitions"][0]["source_deployment_id"]]["component_id"]
                            for path in item["paths"]} if cve == item.get("cve_under_test") else set()))
            for cve in scenario_cves(item)
        }
        grades = {
            cve: {grade for step in steps if (grade := step.get("reproduction_grades", {}).get(cve))}
            for cve in scenario_cves(item)
        }
        for path in item["paths"]:
            observation = path.get("experimental_observation", {})
            if observation:
                grades[observation["cve_id"]].add(observation["source_observation_grade"])
        target = by_id[item["target_deployment_id"]]
        scenarios.append({
            **pick(item, "scenario_id", "description", "target_deployment_id"),
            "target": target.get("display_name") or target["component_id"],
            "sources": [pick(by_id[key], "deployment_id", "component_id", "display_name", "version")
                        for key in sorted(origins)],
            "scope": document.get("assessment_scope") or context,
            "context": context,
            "reproduction": {cve: sorted(values) for cve, values in grades.items()},
            "cves": scenario_cves(item),
            "products_by_cve": subjects,
            "attacker": pick(people[item["attacker_id"]], "description", "capabilities"),
            "windows": observation_windows(document, item),
            "historical_snapshot_at": historical_date,
            "live_evidence_at": document.get("live_evidence", {}).get("observed_at_utc"),
        })
    return {
        "context": context, "provenance": provenance, "version": document["assessment_version"],
        "scope": document.get("assessment_scope"), "scenarios": scenarios,
        "historical_snapshot_at": historical_date,
        "rows": [{**row, "deployment": {
            **pick(record, "deployment_id", "version"),
            "product": record.get("display_name") or record.get("component_id"),
        }} for record in document["cve_assessments"] for row in public_rows(record)]
        if context == "historical" else [],
        "evidence_sources": [
            path.replace("\\", "/") for path in document.get("evidence_provenance", {}).get("runtime_and_architecture_sources", [])
            if isinstance(path, str) and path.startswith(("output/", "output\\"))
        ],
    }


def selected_cve(assessment, cve):
    row = next((item for item in (assessment or {}).get("rows", []) if item["cve_id"] == cve), None)
    if row is None:
        raise AssessmentError("Select a CVE in the current live assessment.")
    return row


def live_source():
    if not (ROOT / LIVE_BUNDLE).exists():
        return None
    document, provenance = artifact(LIVE_BUNDLE)
    if (document.get("assessment_context") != "live"
            or "experiment_governance" in document or "saved_experimental_assessment" in document
            or str(document.get("assessment_version", "")).startswith("research-")
            or any(path.get("experimental_observation")
                   for scenario in document["scenarios"] for path in scenario["paths"])):
        raise AssessmentError("The deployment scenario bundle must contain explicitly scoped live evidence.")
    evidence = document["live_evidence"]
    start = datetime.fromisoformat(evidence["observed_at_utc"])
    stop = datetime.fromisoformat(evidence["valid_until_utc"])
    if start.tzinfo is None or stop.tzinfo is None or start >= stop:
        raise AssessmentError("Live scenario evidence requires a valid observation and expiration window.")
    return document, provenance


def compatible(item, document, assessment, discovery, row):
    evidence = document["live_evidence"]
    start = datetime.fromisoformat(evidence["observed_at_utc"])
    stop = datetime.fromisoformat(evidence["valid_until_utc"])
    captured = datetime.fromisoformat(assessment["captured_at"])
    if ((discovery or {}).get("status") != "COMPLETE" or row["status"] != "AFFECTED"
            or not start <= captured <= datetime.now(timezone.utc) < stop):
        return False
    current = assessment["deployment"]
    endpoints = set()
    for path in item["paths"]:
        for step in path["transitions"]:
            source, target = step["source_deployment_id"], step["target_deployment_id"]
            cves = step.get("cve_ids", [])
            if cves and (set(cves) != {row["cve_id"]} or source != current["deployment_id"]):
                return False
            endpoints.update((source, target))
    if current["deployment_id"] not in endpoints:
        return False

    bindings = evidence["container_ids_by_deployment"]
    known = {item["deployment_id"]: item for item in document["deployments"]}
    discovered = (discovery or {}).get("supported", [])
    for endpoint in endpoints:
        matches = [item for item in discovered if item["deployment_id"] == endpoint]
        if len(matches) != 1 or endpoint not in bindings or not bindings[endpoint]:
            return False
        detected = matches[0]
        if (sorted(detected.get("container_ids") or []) != sorted(bindings[endpoint])
                or (detected["component_id"], detected["version"])
                != (known[endpoint]["component_id"], known[endpoint]["version"])):
            return False
        if endpoint == current["deployment_id"] and detected != current:
            return False
    return True


def coverage(assessment, discovery, cve):
    row = selected_cve(assessment, cve)
    product = assessment["deployment"]["component_id"]
    related, available, errors, outside = [], [], [], []
    live = None
    for context in ("live", *BUNDLES):
        try:
            source = live_source() if context == "live" else artifact(BUNDLES[context])
            if source is None:
                continue
            document, _ = source
            entries = [
                item for item in catalog(context, source)["scenarios"]
                if product in item["products_by_cve"].get(cve, [])
            ]
            if entries and context == "experiment":
                experimental_evidence()
            if context == "live":
                definitions = {item["scenario_id"]: item for item in document["scenarios"]}
                available = [
                    item for item in entries
                    if compatible(definitions[item["scenario_id"]], document, assessment, discovery, row)
                ]
                outside = [item for item in entries if item not in available]
                if available:
                    live = source
            else:
                related.extend(entries)
        except AssessmentError as error:
            errors.append({"context": context, "message": str(error)})
        except (KeyError, TypeError, AttributeError, IndexError, ValueError):
            errors.append({"context": context, "message": "Invalid scenario evidence. Restore or correct the bundle and try again."})
    state = ("compatible" if available else "unavailable" if errors else "related" if related or outside else "none")
    return {
        "cve": cve, "coverage": state, "compatible": available, "related": related,
        "out_of_scope": outside, "errors": errors,
        "missing": [] if available else [
            "A scenario definition naming this CVE, source deployment, transitions and target.",
            "Deployment identity and configuration evidence for the route, attacker prerequisites, receiver controls and target consequences.",
        ],
    }, live


def evaluate_live(assessment, discovery, cve, scenario_id):
    info, source = coverage(assessment, discovery, cve)
    if not any(item["scenario_id"] == scenario_id for item in info["compatible"]):
        raise AssessmentError("That scenario is not compatible with the current deployment and evidence window.")
    deployment = assessment["deployment"]
    current = selected_cve(assessment, cve)
    record = {
        **deployment, "display_name": deployment["product"], "retrieval": assessment["retrieval"],
        "affected": [current], "discovery_evidence": deployment,
    }
    document, provenance = source
    result = evaluate("live", scenario_id, (merge_live_assessment(document, record), provenance))
    return {**result, "cve": cve, "deployment_id": deployment["deployment_id"]}


def evidence_text(value):
    """Render evidence sentences, omitting configuration blocks and raw records."""
    if isinstance(value, list):
        return [line for item in value for line in evidence_text(item)]
    if isinstance(value, str) and "\n" not in value and not re.search(
        r"(?i)(?:password|passwd|secret|token|credential|authorization)\s*[:=]", value
    ):
        return [value]
    return []


def proposition(value):
    return {
        "status": value["status"],
        "reason": evidence_text(value.get("reason")),
        "sources": [
            {
                "source": source.get("source"),
                "evidence": evidence_text(source.get("evidence")),
                **pick(source["source_value"], "evidence_class", "scope", "supporting_artifact",
                       "supporting_artifact_sha256", "observation_window_utc", "run_id",
                       "source_deployment_id", "target_deployment_id", "thing_id", "run_marker"),
            } if isinstance(source.get("source_value"), dict) else {
                "source": source.get("source"), "evidence": evidence_text(source.get("evidence")),
            }
            for source in value.get("sources", [])
        ],
    }


def evaluate(context, scenario_id, source=None):
    document, provenance = source or artifact(BUNDLES[context])
    selected = next((s for s in document["scenarios"] if s["scenario_id"] == scenario_id), None)
    if not selected:
        raise AssessmentError("That scenario does not belong to the selected saved context.")
    report = build_assessment({**document, "scenarios": [selected]})
    if not report["scenario_results"]:
        raise AssessmentError("The saved scenario could not be evaluated. Check its evidence bundle.")
    result = report["scenario_results"][0]
    by_id = {item["deployment_id"]: item for item in document["deployments"]}
    paths = []
    for path in result["paths"]:
        transitions = []
        for step in path["transitions"]:
            source = step["source_deployment_id"]
            target = step["target_deployment_id"]
            transitions.append({
                **pick(step, "step_id", "transition_type", "cve_ids", "relationship_id"),
                "source": source, "target": target,
                "source_product": by_id[source]["component_id"], "target_product": by_id[target]["component_id"],
                "conditions": {
                    key: {
                        "meaning": CONDITIONS[key],
                        "proposition_id": pid,
                        "definition": document.get("condition_semantics", {}).get(
                            "cve_free_A_G" if key in ("A", "G") and not step["cve_ids"]
                            and "cve_free_A_G" in document.get("condition_semantics", {}) else key
                        ),
                        **proposition(report["propositions"][pid]),
                    }
                    for key, pid in step["condition_proposition_ids"].items()
                },
            })
        paths.append({
            **pick(path, "path_id", "feasibility", "target_impact", "source_impacts"),
            "transitions": transitions,
            "target_evidence": {key: proposition(value) for key, value in path["target_evidence_trace"].items()},
        })
    return {
        **pick(result, "scenario_id", "description", "status", "target_component",
               "feasibility_envelope", "reproduction_scope"),
        "context": context, "provenance": provenance, "captured_at": report["generated_at"],
        "version": report["assessment_version"], "paths": paths,
        "source_deployments": [
            pick(by_id[key], "component_id", "deployment_id", "version")
            for key in dict.fromkeys(path["source_deployment_id"] for path in result["paths"])
        ],
    }


def experimental_evidence(source=None):
    document, _ = source or artifact(BUNDLES["experiment"])
    paths = document["evidence_provenance"]
    exp1, source1 = artifact(paths["experiment_1"])
    exp2, source2 = artifact(paths["experiment_2"])
    readback, source3 = artifact(paths["readback_verification"])
    for key, source in (("experiment_1", source1), ("experiment_2", source2),
                        ("readback_verification", source3)):
        if document["source_hashes"][key] != source["sha256"]:
            raise AssessmentError(f"Saved evidence failed provenance verification: {source['path']}")
    evidence = []
    for number, run, source, start, stop in (
        (1, exp1, source1, "run_started_utc", "run_finished_utc"),
        (2, exp2, source2, "started_utc", "finished_utc"),
    ):
        arms = {}
        for name, arm in run["arms"].items():
            broker = arm["deployment"]
            config = broker["configuration"]
            source_check = re.search(r"(?m)^\s*check_retain_source\s+(\S+)", config)
            row = {
                "deployment": broker["container_name"], "version": broker["runtime_version"],
                "source_check": source_check.group(1) if source_check else None,
                "outcome": arm["assessment"]["outcome"],
                "cleanup": (arm.get("cleanup") or run.get("cleanup", {})).get("outcome"),
                "settings": dict(re.findall(
                    r"(?m)^\s*(protocol|allow_anonymous|persistence)\s+(mqtt|true|false)\s*$", config
                )),
            }
            if number == 1:
                row["counts"] = pick(arm["delivery_counts"], "initial", "stale_original_marker", "replacement_marker")
                row["marker"] = arm["markers"].get("initial")
            else:
                marker = readback[f"{name}_retained_marker"]
                row.update(
                    initial_temperature=arm["normal"]["thing_before"]["attributes"]["temperature"],
                    retained_temperature=arm["retained"]["downstream_observation"]["thing_after"]["attributes"]["temperature"],
                    revocation_enforced=arm["retained"]["revocation"]["enforced"],
                    thing_id=marker["thing_id"], marker=marker["run_marker"], records=marker["row_count"],
                    thing_changed=arm["assessment"]["malicious_thing_changed"],
                    writer_event=arm["assessment"]["malicious_writer_event"],
                    normal_verified=arm["normal"]["verified"],
                    post_control_verified=arm["assessment"]["post_revocation_control_verified"],
                    marker_window=marker.get("retained_observation_window"),
                    rows=[pick(item, "time", "value", "run_marker", "thing_id") for item in marker["rows"]],
                )
            arms[name] = row
        evidence.append({
            "number": number, "cve": run["cve_id"], "run_id": run["run_id"],
            "window": {"start": run[start], "stop": run[stop]}, "source": source, "arms": arms,
        })
    support = readback["control_window_support"]
    return {
        "runs": evidence, "readback": {
            **pick(readback, "status", "verified_at_utc"),
            "source": source3, "window": support["window"],
            "rows": [pick(item, "time", "value", "run_marker", "thing_id") for item in support["rows"]],
        },
    }

def architecture_assessment():
    """Evaluate the six targets in the saved paired study without a live deployment."""
    source = artifact(BUNDLES["experiment"])
    document, provenance = source
    try:
        if document["assessment_version"] != "research-cve-2018-12546-experiment-v9":
            raise AssessmentError("Restore the v9 experimental assessment bundle.")
        evidence = experimental_evidence(source)
        runs = evidence["runs"]
        for arm in ("vulnerable", "control"):
            broker = runs[0]["arms"][arm]
            flow = runs[1]["arms"][arm]
            counts = [broker["counts"]["stale_original_marker"], flow["records"]]
            if any(type(n) is not int or n < 0 for n in counts):
                raise AssessmentError("Invalid delivery or readback count. Check the saved experiment records.")
            if any(type(flow[k]) is not bool for k in ("thing_changed", "writer_event", "revocation_enforced",
                                                        "normal_verified", "post_control_verified")):
                raise AssessmentError("Missing observation state. Check the saved downstream evidence.")
            if any(type(flow[k]) not in (int, float) for k in ("initial_temperature", "retained_temperature")):
                raise AssessmentError("Invalid Thing temperature in the saved downstream evidence.")
            if flow["records"] != len(flow["rows"]) or any(
                row["run_marker"] != flow["marker"] or row["thing_id"] != flow["thing_id"]
                for row in flow["rows"]
            ):
                raise AssessmentError("Readback records do not match the saved marker and isolated Thing.")
        if evidence["readback"]["status"] != "CONFIRMED":
            raise AssessmentError("Restore the confirmed readback record for the saved v9 assessment.")
        profiles = {}
        for scenario in document["scenarios"]:
            cve = scenario["cve_under_test"]
            result = evaluate("experiment", scenario["scenario_id"], source)
            path, = result["paths"]
            target = path["transitions"][-1]["target_product"]
            origin = path["transitions"][0]["source"]
            run = runs[0 if target == "mosquitto" else 1]
            arm, = [key for key, data in run["arms"].items() if data["deployment"] == origin]
            if cve != run["cve"] or cve != "CVE-2018-12546":
                raise AssessmentError("The experiment CVE does not match the evaluated scenario.")
            profiles.setdefault(arm, {})[target] = result
        targets = {"mosquitto", "eclipse_ditto", "influxdb"}
        if any(set(profiles[arm]) != targets for arm in ("vulnerable", "control")):
            raise AssessmentError("Restore the complete v9 bundle with both arms and all three targets.")
        return {"cve": cve, "version": document["assessment_version"], "provenance": provenance,
                "profiles": profiles, "evidence": evidence}
    except AssessmentError:
        raise
    except (KeyError, TypeError, ValueError, IndexError, AttributeError) as error:
        raise AssessmentError("Invalid paired experiment structure. Restore the v9 bundle and its matching evidence files.") from error
