"""Build a passive, snapshot-scoped assessment using the existing EBSR adapter."""
import hashlib
import json
import os
import re
from pathlib import Path
import tempfile

from architecture import architecture
from ebsr_adapter import EBSRAdapterError, merge_live_assessment
from . import passive, service


PRODUCTS = {"mosquitto": "Mosquitto", "ditto": "Eclipse Ditto", "eclipse_ditto": "Eclipse Ditto", "influxdb": "InfluxDB"}
SUPPORTED_PRODUCTS = set(PRODUCTS.values())


def _supported_edges():
    """Return architecture edges whose endpoints are implemented assessable products."""
    return [
        (source, target)
        for source, targets in architecture.items()
        if source in SUPPORTED_PRODUCTS
        for target in targets
        if target in SUPPORTED_PRODUCTS
    ]


def architecture_position(component_id):
    """Describe the component's position without implying that a flow exists."""
    product = PRODUCTS[component_id]
    incoming = sorted(source for source, target in _supported_edges() if target == product)
    outgoing = sorted(target for source, target in _supported_edges() if source == product)
    if not outgoing:
        position, label = "terminal", "Terminal supported component"
    elif not incoming:
        position, label = "entry", "Entry supported component"
    else:
        position, label = "intermediate", "Intermediate supported component"
    return {"position": position, "label": label, "incoming_products": incoming,
            "outgoing_products": outgoing, "terminal_component": position == "terminal"}


def _validate_source(discovery, assessment):
    """Validate the selected source deployment independently of route availability."""
    source = assessment["deployment"]
    rows = discovery["supported"]

    def bound(row):
        return (row.get("assessable") and row.get("container_ids")
                and sum(item["deployment_id"] == row["deployment_id"] for item in rows) == 1)

    if source.get("component_id") not in PRODUCTS:
        raise service.AssessmentError("This component has no supported assessment context.")
    if discovery["status"] != "COMPLETE" or not bound(source) or source not in rows:
        raise service.AssessmentError("Deployment identity changed or is incomplete. Discover and scan again.")
    return source, rows, bound


def _potential_consequences(cve_row):
    """Expose advisory consequence categories without treating them as observations."""
    metric = (cve_row.get("cvss") or {}).get("primary") or {}
    vector = str(metric.get("vector") or "")
    names = {"C": "confidentiality", "I": "integrity", "A": "availability"}
    categories = []
    for key, name in names.items():
        match = re.search(rf"(?:^|/){key}:([HLN])", vector)
        if match and match.group(1) != "N":
            categories.append(name)
    return {
        "status": "ADVISORY_CATEGORY_ONLY",
        "categories": categories,
        "reason": ("Derived from the selected CVSS impact vector as potential consequence categories. "
                   "They are not observations and carry no target magnitude."),
        "source": service.pick(metric, "version", "score", "vector", "source", "source_type"),
    }


def not_assessed_guidance(reason, action="refresh"):
    """Return guidance that never upgrades missing evidence into a finding."""
    if action == "route":
        next_action = {
            "kind": "CONFIRM_ROUTE",
            "label": "Confirm the intended deployment route",
            "detail": "Choose the route whose source and targets are supported by the deployment evidence.",
        }
    else:
        next_action = {
            "kind": "PASSIVE_REFRESH",
            "label": "Refresh read-only evidence",
            "detail": ("Re-collect Docker and configuration evidence, then apply the same CVE and route. "
                       "This does not publish messages or run a vulnerability test."),
        }
    return {
        "verified": [],
        "unknown": [reason],
        "next_action": next_action,
        "refresh_available": True,
    }


def _relationship_evidence(source, target, discovery, scan):
    """Describe one discovered deployment pair without promoting connectivity."""
    raw = connection(source, target, None, None)
    relation = passive.relationship(source, target, discovery, scan, raw["shared_networks"])
    return {
        "source_deployment_id": source["deployment_id"],
        "target_deployment_id": target["deployment_id"],
        "source_product": source.get("product") or PRODUCTS[source["component_id"]],
        "target_product": target.get("product") or PRODUCTS[target["component_id"]],
        "shared_networks": raw["shared_networks"],
        "matching_endpoint_settings": raw["matching_endpoint_settings"],
        "verification": relation["state"],
        "verification_reason": relation["reason"],
        "verification_meaning": relation["meaning"],
        "operator_reference": None,
        "records": relation["records"],
        "inventory": relation["inventory"],
        "configuration": ("VERIFIED" if relation["state"] in
                          (passive.VERIFIED_CONFIGURATION, passive.OBSERVED_COMMUNICATION)
                          else "NOT_CONFIGURED" if relation["state"] == passive.NOT_CONFIGURED else "UNKNOWN"),
        "communication": "OBSERVED" if relation["state"] == passive.OBSERVED_COMMUNICATION else "UNKNOWN",
        "propagation": "UNKNOWN",
        "collected_at": discovery["captured_at"],
        "limitation": "A configured endpoint or ordinary traffic cannot establish CVE-specific propagation.",
    }


def _neighbour_relationships(source, rows, bound, discovery, scan):
    """Collect evidence for supported edges adjacent to the selected deployment."""
    product = PRODUCTS[source["component_id"]]
    result = []
    seen = set()
    for source_product, target_product in _supported_edges():
        if product not in (source_product, target_product):
            continue
        sources = [row for row in rows if PRODUCTS.get(row.get("component_id")) == source_product and bound(row)]
        targets = [row for row in rows if PRODUCTS.get(row.get("component_id")) == target_product and bound(row)]
        for left in sources:
            for right in targets:
                if source["deployment_id"] not in (left["deployment_id"], right["deployment_id"]):
                    continue
                key = (left["deployment_id"], right["deployment_id"])
                if key not in seen:
                    seen.add(key)
                    result.append(_relationship_evidence(left, right, discovery, scan))
    return result


def bounded_context(discovery, assessment, cve_row, classification):
    """Return an explainable component context when numerical EBSR is unavailable."""
    source, rows, bound = _validate_source(discovery, assessment)
    position = architecture_position(source["component_id"])
    relationships = _neighbour_relationships(source, rows, bound, discovery, assessment["captured_at"])
    supported_states = {passive.VERIFIED_CONFIGURATION, passive.OBSERVED_COMMUNICATION}
    verified_relationships = [item for item in relationships if item["verification"] in supported_states]
    if relationships and len(verified_relationships) == len(relationships):
        path_status = "VERIFIED_ARCHITECTURE_RELATIONSHIPS"
    elif verified_relationships:
        path_status = "PARTIAL_ARCHITECTURE_EVIDENCE"
    else:
        path_status = "NO_VERIFIED_ARCHITECTURE_PATH"

    facts = [f"Selected deployment: {source.get('product') or PRODUCTS[source['component_id']]} "
             f"{source['version']} ({source['deployment_id']}).",
             f"Architecture position: {position['label']}."]
    missing = []
    for relation in relationships:
        pair = f"{relation['source_product']} to {relation['target_product']}"
        if relation["configuration"] == "VERIFIED":
            facts.append(f"{pair}: application configuration was verified for the exact deployments.")
        elif relation["configuration"] == "NOT_CONFIGURED":
            missing.append(f"{pair}: no matching configuration was found in the inspected scope.")
        else:
            missing.append(f"{pair}: the application relationship remains unknown. {relation['verification_reason']}")
        if relation["communication"] == "OBSERVED":
            facts.append(f"{pair}: matching ordinary communication was observed in the collection window.")
        else:
            missing.append(f"{pair}: successful application communication was not observed.")
    if position["terminal_component"]:
        facts.append("No supported downstream component is inferred for this deployment. This is a component-level assessment.")
    elif not any(item["target_deployment_id"] == source["deployment_id"] for item in relationships):
        missing.append("No verified upstream architecture relationship is represented in this discovery snapshot.")

    applicability_reason = cve_row.get("reason") or "No applicability reason was recorded."
    if cve_row["status"] == "UNKNOWN":
        missing.insert(0, f"CVE applicability remains UNKNOWN for this exact deployment. {applicability_reason}")
    elif cve_row["status"] == "AFFECTED":
        missing.insert(0, "The CVE is applicable, but no supported numerical architecture path was available for evaluation.")
    else:
        missing.insert(0, f"CVE applicability is {cve_row['status']} for this exact deployment. {applicability_reason}")
    missing.append("No deployment-specific evidence establishes the CVE prerequisites, transition capability (K), receiver processing or controls (Y), or target C/I/A consequence.")

    actions = [
        {"action_id": "resolve-applicability", "kind": "APPLICABILITY_EVIDENCE",
         "label": "Resolve deployment-specific applicability",
         "detail": ("Review the authoritative advisory, affected product ranges and this deployment's image/version evidence. "
                    "Do not infer applicability from CVSS alone.")},
        {"action_id": "map-cve-prerequisites", "kind": "CONFIGURATION_REVIEW",
         "label": "Map the CVE prerequisites to this deployment",
         "detail": ("Collect read-only vendor documentation and component configuration that explicitly establish or exclude the "
                    "advisory's prerequisites. Missing evidence remains UNKNOWN.")},
    ]
    for relation in relationships:
        if relation["verification"] not in supported_states:
            actions.append({
                "action_id": f"resolve-{relation['source_deployment_id']}-{relation['target_deployment_id']}",
                "kind": "PASSIVE_REFRESH",
                "label": f"Resolve {relation['source_product']} to {relation['target_product']} evidence",
                "detail": relation["verification_reason"],
            })
    if position["terminal_component"]:
        actions.append({
            "action_id": "component-local-consequence",
            "kind": "COMPONENT_IMPACT_REVIEW",
            "label": "Assess component-local consequences after applicability",
            "detail": ("If applicability becomes AFFECTED, assess this component's C/I/A consequence from CVE-specific "
                       "evidence. No downstream path is required or inferred."),
        })
    actions.append({
        "action_id": "defer-exploit-validation",
        "kind": "CONTROLLED_VALIDATION_REQUIRED",
        "label": "Defer validation until applicability and prerequisites are established",
        "detail": ("Do not treat connectivity as propagation. A separate bounded experiment would require explicit "
                   "applicability, prerequisites, target and cleanup design."),
    })
    retrieval_status = (assessment.get("retrieval") or {}).get("status")
    retrieval_limited = retrieval_status in ("FAILED", "MALFORMED", None)

    return {
        "deployment": service.pick(source, "deployment_id", "component_id", "product", "version",
                                   "version_source", "container_ids", "image_id", "image_digest"),
        "cve": service.pick(cve_row, "cve_id", "status", "reason"),
        "assessment_states": {
            "applicability": {"status": cve_row["status"], "classification": classification,
                              "reason": applicability_reason},
            "architecture_path": {"status": path_status, "classification": path_status,
                                  "reason": ("No adjacent endpoint pair has evidence-supporting configuration or communication."
                                             if path_status == "NO_VERIFIED_ARCHITECTURE_PATH"
                                             else "Adjacent relationship evidence is kept separate from path propagation.")},
            "cve_specific_consequences": {
                "status": "INSUFFICIENT_EVIDENCE", "classification": "INSUFFICIENT_CVE_SPECIFIC_EVIDENCE",
                "reason": "No CVE-specific transition, receiver, or target-consequence evidence is attached.",
            },
            "engine": {
                "status": "INPUT_EVIDENCE_UNAVAILABLE" if retrieval_limited else "AVAILABLE_NOT_EXERCISED",
                "classification": "ASSESSMENT_ENGINE_LIMITATION" if retrieval_limited else "AVAILABLE_NOT_EXERCISED",
                "reason": (f"Numerical EBSR was not run because the applicability retrieval status is {retrieval_status}."
                           if retrieval_limited else
                           "Numerical EBSR remains available, but was not run without a supported CVE-bound path or "
                           "confirmed applicability."),
            },
        },
        "architecture_position": position,
        "terminal_component": position["terminal_component"],
        "relationships": relationships,
        "known_facts": facts,
        "cve_specific_evidence": {
            "known_vulnerability_prerequisites": {
                "status": "NOT_ESTABLISHED",
                "items": [],
                "reason": "The selected assessment contains no deployment-bound prerequisite evidence for this CVE.",
            },
            "transition_capability": {"status": "UNKNOWN", "reason": "CVE-specific capability (K) is not established."},
            "receiver_processing": {"status": "UNKNOWN", "reason": "Receiver processing and controls (Y) are not established."},
            "target_consequence": {
                "status": "UNKNOWN",
                "reason": "No target C/I/A consequence or magnitude is established for this deployment.",
            },
        },
        "potential_consequence_categories": _potential_consequences(cve_row),
        "missing_evidence": list(dict.fromkeys(missing)),
        "recommended_actions": actions,
        "numerical_assessment": {
            "status": "NOT_CALCULATED",
            "reason": ("No feasibility interval or target C/I/A magnitude is calculated for this context."),
        },
        "provenance": {
            "discovery_captured_at": discovery["captured_at"],
            "assessment_captured_at": assessment["captured_at"],
            "applicability": assessment.get("provenance"),
            "retrieval": assessment.get("retrieval"),
            "inspections": [service.pick(item, "container_id", "started", "finished", "connection_inventory")
                            for item in source.get("inspections", [])],
            "relationships": [{"source_deployment_id": item["source_deployment_id"],
                               "target_deployment_id": item["target_deployment_id"],
                               "verification": item["verification"], "records": item["records"],
                               "inventory": item["inventory"]} for item in relationships],
        },
    }


def bounded_guidance(context):
    """Build the same evidence-guided envelope used by evaluated scenarios."""
    states = context["assessment_states"]
    action = context["recommended_actions"][0]
    return {
        "verified": context["known_facts"],
        "unknown": context["missing_evidence"],
        "next_action": {"kind": action["kind"], "label": action["label"], "detail": action["detail"]},
        "refresh_available": True,
        "layers": [
            {"key": "applicability", "label": "Deployment-specific applicability",
             "status": states["applicability"]["status"]},
            {"key": "relationship", "label": "Architecture relationships",
             "status": states["architecture_path"]["status"]},
            {"key": "cve", "label": "CVE-specific consequences",
             "status": states["cve_specific_consequences"]["status"]},
            {"key": "engine", "label": "Numerical EBSR",
             "status": states["engine"]["status"]},
        ],
    }


def _next_action(state):
    actions = {
        passive.OBSERVED_COMMUNICATION: {
            "kind": "CONTROLLED_VALIDATION",
            "label": "Review controlled CVE validation",
            "detail": ("Ordinary traffic is observed. Review a bounded experiment before testing whether the "
                       "selected CVE changes this deployment."),
        },
        passive.VERIFIED_CONFIGURATION: {
            "kind": "CONTROLLED_VALIDATION",
            "label": "Review bounded traffic validation",
            "detail": ("The application connection is configured, but traffic is not observed. Review a bounded "
                       "validation using the exact deployment and configuration."),
        },
        passive.NETWORK_ONLY: {
            "kind": "PASSIVE_REFRESH",
            "label": "Resolve configuration evidence",
            "detail": ("The components share a Docker network, but no application connection is established. "
                       "Refresh read-only evidence after resolving API access or deployment binding."),
        },
        passive.NOT_CONFIGURED: {
            "kind": "PASSIVE_REFRESH",
            "label": "Trace the data path",
            "detail": ("No matching application connection is configured. Inspect for an intermediate service, "
                       "then refresh read-only evidence."),
        },
        passive.UNKNOWN: {
            "kind": "PASSIVE_REFRESH",
            "label": "Resolve unknown evidence",
            "detail": ("Connection evidence is incomplete or inaccessible. Resolve the recorded limitation and "
                       "refresh read-only evidence."),
        },
    }
    return actions[state]


def _aggregate(values):
    present = set(values)
    for value in ("X", "F", "U"):
        if value in present:
            return value
    return "T" if present == {"T"} else "U"


def assessment_guidance(links, result):
    """Describe supported facts, unresolved questions and the next safe validation step."""
    verified, unknown = [], []
    paths = result.get("paths", [])
    transitions = [step for path in paths for step in path.get("transitions", [])]
    a_status = _aggregate(step["conditions"]["A"]["status"] for step in transitions)
    if not links and a_status == "T":
        verified.append("The selected CVE is applicable to the exact component deployment.")
        unknown.append("No cross-deployment architecture path is claimed; this is a component-level assessment.")
    for link in links:
        pair = f"{link['source_product']} to {link['target_product']}"
        if link["configuration"] == "VERIFIED":
            verified.append(f"{pair}: an application connection naming the exact deployments was verified.")
        elif link["configuration"] == "NOT_CONFIGURED":
            unknown.append(f"{pair}: no matching application connection was found in the inspected scope.")
        else:
            unknown.append(f"{pair}: the application connection configuration remains unknown.")
        if link["communication"] == "OBSERVED":
            verified.append(f"{pair}: relevant ordinary communication was observed in the collection window.")
        else:
            unknown.append(f"{pair}: successful application communication was not observed.")
    k_status = _aggregate(step["conditions"]["K"]["status"] for step in transitions)
    y_status = _aggregate(step["conditions"]["Y"]["status"] for step in transitions)
    impacts = [step["status"] for path in paths for step in path.get("target_impact", {}).values()]
    impact_status = _aggregate(impacts)
    unknown.extend([
        "CVE-specific transition capability (K) remains unknown unless a matching experiment establishes it.",
        "Receiver processing and controls (Y) remain unknown unless evidence establishes those claims.",
        "Target confidentiality, integrity and availability consequences remain unknown unless separately measured.",
    ])
    states = {link["verification"] for link in links}
    if not states:
        action = _next_action(passive.UNKNOWN)
    elif states & {passive.NETWORK_ONLY, passive.UNKNOWN}:
        action = _next_action(passive.UNKNOWN)
    elif passive.NOT_CONFIGURED in states:
        action = _next_action(passive.NOT_CONFIGURED)
    elif passive.VERIFIED_CONFIGURATION in states:
        action = _next_action(passive.VERIFIED_CONFIGURATION)
    else:
        action = _next_action(passive.OBSERVED_COMMUNICATION)
    return {
        "verified": verified,
        "unknown": unknown,
        "next_action": action,
        "refresh_available": True,
        "layers": [
            {"key": "configuration", "label": "Application relationship configuration", "status": (
                "COMPONENT_ONLY" if not links else
                "VERIFIED" if all(link["configuration"] == "VERIFIED" for link in links)
                else "NOT_CONFIGURED" if any(link["configuration"] == "NOT_CONFIGURED" for link in links)
                else "UNKNOWN")},
            {"key": "communication", "label": "Observed application communication", "status": (
                "COMPONENT_ONLY" if not links else
                "OBSERVED" if any(link["communication"] == "OBSERVED" for link in links) else "UNKNOWN")},
            {"key": "cve", "label": "CVE-specific behaviour", "status": k_status},
            {"key": "impact", "label": "Target consequence", "status": impact_status},
        ],
        "receiver": {"label": "Receiver processing and controls", "status": y_status},
    }


def evidence_signature(discovery, assessment):
    """Hash substantive evidence while ignoring collection timestamps."""
    ignored = {"captured_at", "started", "finished", "timestamp", "observed_at", "observed_at_utc",
               "discovered_at", "scan_time", "lastMessageAt", "last_accepted_at"}

    def stable(value):
        if isinstance(value, dict):
            return {key: stable(item) for key, item in value.items()
                    if key not in ignored and not key.endswith("_at")}
        if isinstance(value, list):
            return [stable(item) for item in value]
        return value

    payload = {
        "discovery_status": (discovery or {}).get("status"),
        "supported": (discovery or {}).get("supported", []),
        "assessment": {
            "deployment": (assessment or {}).get("deployment"),
            "rows": (assessment or {}).get("rows", []),
            "retrieval": service.pick((assessment or {}).get("retrieval", {}), "status", "received", "total_results"),
        },
    }
    return hashlib.sha256(json.dumps(stable(payload), ensure_ascii=False,
                                    sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def routes(discovery, assessment):
    source, rows, bound = _validate_source(discovery, assessment)
    paths = [[source]] if architecture_position(source["component_id"])["terminal_component"] else []
    def extend(path):
        for row in rows:
            if (PRODUCTS.get(row.get("component_id")) in architecture.get(PRODUCTS[path[-1]["component_id"]], []) and bound(row)
                    and row not in path):
                candidate = path + [row]
                paths.append(candidate)
                extend(candidate)
    extend([source])
    return paths


def connection(source, target, assertion, reference):
    shared = set()
    settings = set()
    for left in source.get("architecture_metadata", []):
        for right in target.get("architecture_metadata", []):
            networks = set(left.get("networks", {})) & set(right.get("networks", {}))
            shared.update(networks)
            for network in networks:
                for origin, peer, prefix in ((right, left, "MQTT"), (left, right, "INFLUXDB")):
                    for key, host in origin.get("endpoint_hosts", {}).items():
                        if key.startswith(prefix) and host in peer["networks"][network]:
                            settings.add(key)
    return {"source": source["deployment_id"], "target": target["deployment_id"],
            "shared_networks": sorted(shared), "matching_endpoint_settings": sorted(settings),
            "user_evidence": assertion, "operator_reference":reference, "communication": "UNKNOWN", "propagation": "UNKNOWN",
            "basis": ("Configured endpoint reference" if settings else
                      "Operator-reviewed configuration" if assertion == "configuration" else
                      "Operator-confirmed intended route" if assertion == "intended" else
                      "Shared Docker network" if shared else "Reference architecture only")}


def store_bundle(encoded, directory, digest):
    directory.mkdir(parents=True, exist_ok=True)
    dest = directory / (digest + ".json")
    if not dest.exists():
        with tempfile.NamedTemporaryFile(dir=directory, delete=False) as stream:
            temp = Path(stream.name)
        try:
            temp.write_bytes(encoded)
            os.replace(temp, dest)
        finally:
            temp.unlink(missing_ok=True)
    elif dest.read_bytes() != encoded:
        raise service.AssessmentError("The saved scenario failed its content check. Inspect its provenance.")


def analyze(discovery, assessment, request, directory, require_explicit_route=False):
    if not assessment or not discovery:
        raise service.AssessmentError("Discover and scan a deployment first.")
    source = assessment["deployment"]
    if (request.get("deployment_id") != source["deployment_id"]
            or request.get("captured_at") != assessment["captured_at"]
            or discovery["captured_at"] > assessment["captured_at"]):
        raise service.AssessmentError("This scan no longer matches the discovery snapshot. Scan the deployment again.")
    cve = request.get("cve")
    cve_row = service.selected_cve(assessment, cve)
    paths = routes(discovery, assessment)
    options = [[r["deployment_id"] for r in p] for p in paths]
    if cve_row["status"] != "AFFECTED":
        classification = ("APPLICABILITY_UNKNOWN" if cve_row["status"] == "UNKNOWN"
                          else "APPLICABILITY_NOT_AFFECTED")
        context = bounded_context(discovery, assessment, cve_row, classification)
        reason = (f"{cve}: deployment applicability is {cve_row['status']}; numerical EBSR was not calculated. "
                  "A component-bounded evidence context is available.")
        guidance = bounded_guidance(context)
        return {"status": "NOT_ASSESSED", "assessment_state": classification, "reason": reason,
                "bounded_context": context, "guidance": guidance}
    if not paths:
        context = bounded_context(discovery, assessment, cve_row, "NO_VERIFIED_ARCHITECTURE_PATH")
        reason = ("The CVE is applicable to this deployment, but no supported downstream deployment with a unique "
                  "runtime identity was discovered. Numerical EBSR was not calculated.")
        guidance = bounded_guidance(context)
        return {"status": "NOT_ASSESSED", "assessment_state": "NO_VERIFIED_ARCHITECTURE_PATH",
                "reason": reason, "bounded_context": context, "guidance": guidance}
    choice = request.get("route")
    if choice is None:
        if len(paths) == 1:
            choice = options[0]
        elif sum(len(p) == 2 for p in paths) != 1:
            reason = "Select the intended deployment route."
            return {"status": "CHOOSE_ROUTE", "routes": options, "reason": reason,
                    "guidance": not_assessed_guidance(reason, "route")}
        else:
            choice = next(option for option in options if len(option) == 2)
    if choice not in options:
        if require_explicit_route:
            reason = ("The previously selected route is no longer supported by the refreshed deployment "
                      "identities. Confirm an available route before evaluating it.")
            return {"status": "CHOOSE_ROUTE", "routes": options, "reason": reason, "route_invalidated": True,
                    "guidance": not_assessed_guidance(reason, "route")}
        raise service.AssessmentError("The selected route is unsupported or its deployment identities no longer match.")
    path = paths[options.index(choice)]
    assertion = request.get("assertion")
    if assertion not in (None, "intended", "configuration"):
        raise service.AssessmentError("Choose an available relationship evidence type.")
    reference = request.get("reference") or None
    if reference and (not assertion or not isinstance(reference, str) or
                      not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", reference)):
        raise service.AssessmentError("Use a short evidence document name or record ID with a confirmed relationship.")
    # A confirmation describes only the last selected edge, never the full path.
    links = [connection(a, b, assertion if i == len(path)-2 else None, reference if i == len(path)-2 else None)
             for i, (a, b) in enumerate(zip(path, path[1:]))]
    nodes = []
    for row in path:
        for member in row.get("architecture_metadata", []):
            if member.get("member_id") and (not passive.instant(discovery["captured_at"]) or
                    passive.instant(passive.utc()) - passive.instant(discovery["captured_at"]) > passive.MAX_AGE):
                raise service.AssessmentError("The Docker evidence snapshot is older than 15 minutes. Discover and scan again.")
            if member.get("member_id") and not passive.binding_unchanged(member):
                raise service.AssessmentError("Container identity or start time changed or cannot be verified. Discover and scan again.")
        records = row.get("inspections", [])
        nodes.append({**service.pick(row, "deployment_id", "component_id", "product", "version", "container_ids",
                                     "version_source", "image_digest", "image_id"),
                      "members": row.get("architecture_metadata", []),
                      "inspections": [e for e in records if passive.valid(row,e,assessment["captured_at"])],
                      "issues": [issue for e in records for issue in e.get("issues", [])] +
                                (["Incomplete or stale evidence. Rediscover to refresh."] if any(
                                 not passive.valid(row,e,assessment["captured_at"]) for e in records) else [])})
    prerequisites = []
    prerequisite_evidence = []
    if cve == "CVE-2018-12546" and source["component_id"] == "mosquitto":
        for observation in nodes[0]["inspections"]:
            config = observation.get("mosquitto_file", {})
            directives = config.get("directives", {})
            security = observation.get("mosquitto_security", {})
            for name in ("check_retain_source", "retain_available", "allow_anonymous"):
                if name in directives:
                    prerequisites.append(f"The inspected broker file declares {name}=" + ", ".join(directives[name]) + ".")
            if directives.get("acl_file_present"):
                prerequisites.append("An ACL file is referenced. Its rules and any publisher revocation remain unverified.")
            prerequisite_evidence.append({
                "container_id": observation.get("container_id"),
                "config_source": config.get("source"),
                "config_sha256": config.get("sha256"),
                "authentication_required": security.get("authentication_required"),
                "password_file_referenced": security.get("password_file_referenced"),
                "acl_file_referenced": security.get("acl_file_referenced"),
                "acl_summary": security.get("acl_summary"),
                "retained_message_settings": security.get("retained_message_settings"),
                "publisher_revocation_and_retained_delivery": "UNKNOWN",
                "status": "CONFIGURATION_DECLARED" if security else "UNKNOWN",
                "limitation": security.get("limitation") or "Effective listener and authorization behavior was not verified.",
            })
        prerequisites.append("Retained delivery following an enforced revocation has not been established for this deployment.")
    for edge, a, b in zip(links, path, path[1:]):
        relation = passive.relationship(a, b, discovery, assessment["captured_at"], edge["shared_networks"])
        state = relation["state"]
        basis = {
            passive.OBSERVED_COMMUNICATION: "Observed ordinary application traffic",
            passive.VERIFIED_CONFIGURATION: "Application connection configured",
            passive.NETWORK_ONLY: "Shared Docker network only",
            passive.NOT_CONFIGURED: "No matching application connection configured",
            passive.UNKNOWN: "Application relationship unresolved",
        }[state]
        next_action = _next_action(state)
        edge.update(source_product=a["product"], target_product=b["product"], verification=state,
                    verification_reason=relation["reason"], verification_meaning=relation["meaning"],
                    records=relation["records"], inventory=relation["inventory"],
                    configuration=("VERIFIED" if state in (passive.VERIFIED_CONFIGURATION, passive.OBSERVED_COMMUNICATION)
                                   else "NOT_CONFIGURED" if state == passive.NOT_CONFIGURED else "UNKNOWN"),
                    communication="OBSERVED" if state == passive.OBSERVED_COMMUNICATION else "UNKNOWN",
                    propagation="UNKNOWN", next_action=next_action["detail"],
                    next_action_kind=next_action["kind"], next_action_label=next_action["label"],
                    observed_at=discovery["captured_at"], transition_type="DF",
                    limitation="A configured endpoint or ordinary traffic cannot establish CVE-specific propagation.")
        edge["basis"] = basis
    scenario_id = "live-" + hashlib.sha256(json.dumps([choice,cve,assessment["captured_at"]]).encode()).hexdigest()[:16]
    transitions, relationships = [], []
    if not links:
        transitions.append({
            "source_deployment_id": source["deployment_id"],
            "target_deployment_id": source["deployment_id"],
            "transition_type": "DIRECT",
            "relationship_id": None,
            "step_id": "component-direct",
            "cve_ids": [cve],
            "conditions": {key: ("T" if key == "A" else "U") for key in "AGHKY"},
        })
    for i, link in enumerate(links):
        pair = {"source_deployment_id":link["source"], "target_deployment_id":link["target"],
                "transition_type":"DF", "relationship_id":f"flow-{i}"}
        relationship_status = ("SUPPORTED" if link["verification"] in
                               (passive.VERIFIED_CONFIGURATION, passive.OBSERVED_COMMUNICATION) else
                               "NOT_SUPPORTED" if link["verification"] == passive.NOT_CONFIGURED else "UNKNOWN")
        relationships.append({**pair, "status":relationship_status,
                              "verification":link["verification"],
                              "evidence":[link["basis"], link["verification_reason"],
                                          *[f"{r['source']} at {r['timestamp']} for {r['connection_id']}"
                                            for r in link["records"]]]})
        transitions.append({**pair, "step_id":f"step-{i}", "cve_ids":[cve] if i == 0 else [],
                            "conditions":{k: ("T" if k == "A" and i == 0 else "U") for k in "AGHKY"}})
    component_scope = len(path) == 1
    scenario = {"scenario_id":scenario_id, "attacker_id":"unspecified", "target_deployment_id":choice[-1],
                "description":(f"{cve}: component-level assessment of {source['product']} {source['version']}."
                               if component_scope else
                               f"{cve}: potential effects on {path[-1]['product']} from {source['product']} {source['version']}."),
                "cve_under_test":cve, "paths":[{"path_id":"candidate", "target_deployment_id":choice[-1],
                                                "transitions":transitions}]}
    document = merge_live_assessment({
        "assessment_version":"deployment-snapshot-1", "assessment_context":"live",
        "snapshot":{"discovered_at":discovery["captured_at"], "scan_time":assessment["captured_at"],
                    "container_ids_by_deployment":{r["deployment_id"]:r["container_ids"] for r in path},
                    "connections":links, "nodes":nodes, "prerequisite_findings":prerequisites,
                    "cve_prerequisites":prerequisite_evidence,
                    "relationship_state_meanings":passive.RELATIONSHIP_STATE_MEANINGS,
                    "evidence_scope":"Discovery and vulnerability scan snapshot",
                    "applicability_source":assessment["provenance"]},
        "deployments":[{**service.pick(r,"deployment_id","component_id","version"),
                        "discovery_evidence":r} for r in path],
        "attacker_profiles":[{"attacker_id":"unspecified","description":"Attacker prerequisites unverified"}],
        "architecture_evidence":relationships, "scenarios":[scenario]},
        {**source, "affected":[cve_row], "retrieval":assessment["retrieval"], "discovery_evidence":source})
    encoded = json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2).encode()
    digest = hashlib.sha256(encoded).hexdigest()
    provenance = {"path": "/".join((*directory.parts[-2:], digest + ".json")), "sha256": digest}
    try:
        result = service.evaluate("live", scenario_id, (document, provenance))
    except EBSRAdapterError as exc:
        raise service.AssessmentError("The generated scenario could not be evaluated: " + str(exc)) from exc
    store_bundle(encoded, directory, digest)
    result.update(cve=cve, deployment_id=source["deployment_id"], snapshot=document["snapshot"],
                  assessment_type="Deployment-scoped architecture assessment", routes=options, route=choice,
                  target_product=path[-1]["product"], target_version=path[-1]["version"],
                  component_level=component_scope,
                  architecture_position=architecture_position(source["component_id"]))
    guidance = assessment_guidance(links, result)
    result["evidence_guidance"] = guidance
    return {"status":"EVALUATED", "result":result, "guidance":guidance}
