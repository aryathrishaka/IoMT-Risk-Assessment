# =========================================================
# IoMT Risk Assessment
# NVD -> CVE -> CVSS -> Architecture / Propagation
# =========================================================


import argparse

from architecture import (
    architecture,
    get_attack_path,
    get_relationship
)



from risk_model import (
    calculate_propagation_score,
    calculate_path_propagation
)

from nvd_api import (
    RETRIEVAL_COMPLETE,
    RETRIEVAL_PARTIAL,
    RETRIEVAL_FAILED,
    RETRIEVAL_MALFORMED,
    search_cves_by_keyword_with_status,
    extract_cve_information
)

from applicability import (
    AFFECTED,
    UNKNOWN,
    NOT_AFFECTED,
    cvss_summary,
    evaluate_applicability,
)

from cvss_model import calculate_cvss

from version_detector import detect_versions

from ebsr_adapter import (
    build_assessment as build_ebsr_assessment,
    load_input as load_ebsr_input,
    merge_live_assessment,
    print_assessment_summary,
    replay_assessment,
    save_assessment,
)


NVD_SEARCH_TERMS = {
    "Mosquitto": "mosquitto",
    "Mosquitto Vulnerable Lab": "mosquitto",
    "InfluxDB": "influxdb",
    "Eclipse Ditto": "ditto"
}


# =========================================================
# Display Architecture
# =========================================================

def show_architecture():

    print()
    print("IoMT Architecture")
    print("=================")

    for source, destinations in architecture.items():

        if destinations:

            for destination in destinations:

                print(
                    f"{source} -> {destination}"
                )

        else:

            print(
                f"{source} -> END"
            )


# =========================================================
# Detect Software Automatically
# =========================================================

def get_available_software():

    detected = detect_versions()

    available = {}

    for software, info in detected.items():

        version = info.get("version")

        if info.get("diagnostic"):

            available[software] = {

                "diagnostic": True,

                "component_id":
                    info.get("component_id"),

                "deployment_id":
                    info.get("deployment_id"),

                "architecture_component":
                    info.get("display_name"),

                "cpe":
                    info.get("cpe"),

                "status":
                    info.get("status"),

                "version":
                    version,

                "container":
                    info.get("container"),

                "image":
                    info.get("image"),

                "image_digest":
                    info.get("image_digest"),

                "version_source":
                    info.get("version_source"),

                "runtime_probe":
                    info.get("runtime_probe"),

                "classification_source":
                    info.get("classification_source"),

                "reason":
                    info.get("reason")
                    or info.get("error"),

                "discovery_evidence":
                    info
            }

            continue

        # We only use a specific detected version.
        # "latest" is not sufficient for precise
        # vulnerability lookup.

        if (
            info.get("status") == "Detected"
            and version
            and version != "latest"
        ):

            available[software] = {

                "software":
                    info.get("nvd_search_term")
                    or NVD_SEARCH_TERMS.get(
                        software,
                        software.lower()
                    ),

                "applicability_component":
                    info.get("component_id")
                    or software,

                "architecture_component":
                    info.get("display_name")
                    or software,

                "component_name":
                    info.get("display_name")
                    or software,

                "deployment_id":
                    info.get("deployment_id"),

                "cpe":
                    info.get("cpe"),

                "image_id":
                    info.get("image_id"),

                "image_tag":
                    info.get("image_tag"),

                "image_digest":
                    info.get("image_digest"),

                "image_repository":
                    info.get("image_repository"),

                "version_source":
                    info.get("version_source"),

                "application_version_evidence":
                    info.get("application_version_evidence"),

                "runtime_probe":
                    info.get("runtime_probe"),

                "classification_source":
                    info.get("classification_source"),

                "discovery_evidence":
                    info,

                "version":
                    version,

                "container":
                    info["container"],

                "image":
                    info["image"],

                "diagnostic":
                    False
            }

    return available


# =========================================================
# NVD Lookup
# =========================================================

def get_vulnerabilities(
    component,
    search_term,
    version
):

    print()

    print(
        f"Searching NVD for: "
        f"{search_term} {version}"
    )

    retrieval = search_cves_by_keyword_with_status(
        search_term,
        results_per_page=100
    )

    candidates = retrieval["items"]

    print(
        f"NVD retrieval status: "
        f"{retrieval['status']}"
    )

    affected = []
    unknown = []
    not_affected = []
    applicability_records = []
    assessment_groups = {
        "affected": [],
        "unknown": [],
        "not_affected": []
    }

    for item in candidates:

        provenance = evaluate_applicability(
            item,
            component,
            version
        )
        status = provenance["status"]
        reason = provenance["reason"]
        applicability_records.append(provenance)
        cve_info = extract_cve_information(item)
        assessment_row = {
            "cve_id": cve_info["id"],
            "status": status,
            "reason": reason,
            "cvss": cvss_summary(item),
            "description": cve_info["description"][:200],
            "applicability": provenance
        }

        if status == AFFECTED:

            affected.append(item)
            assessment_groups["affected"].append(
                assessment_row
            )

        elif status == UNKNOWN:

            unknown.append({
                "item": item,
                "status": status,
                "reason": reason
            })
            assessment_groups["unknown"].append(
                assessment_row
            )

        elif status == NOT_AFFECTED:

            not_affected.append(item)
            assessment_groups["not_affected"].append(
                assessment_row
            )

    retrieval["applicability"] = applicability_records
    retrieval["assessments"] = assessment_groups

    return affected, unknown, retrieval


def show_retrieval_status(retrieval):

    print()

    print(
        "NVD Retrieval"
    )

    print(
        "============="
    )

    print(
        f"Status: {retrieval['status']}"
    )

    print(
        f"Unique valid CVE records received: "
        f"{retrieval['received']}"
    )

    if retrieval["total_results"] is None:

        print(
            "NVD reported total: unavailable"
        )

    else:

        print(
            f"NVD reported total: "
            f"{retrieval['total_results']}"
        )

    if retrieval["error"]:

        print(
            f"Retrieval error: {retrieval['error']}"
        )

    if retrieval["status"] == RETRIEVAL_PARTIAL:

        print()

        print(
            "WARNING: NVD retrieval was incomplete. "
            "The assessment only covers the records "
            "that were successfully retrieved; absence "
            "of additional vulnerabilities cannot be concluded."
        )


# =========================================================
# Show CVEs
# =========================================================

def show_vulnerabilities(
    affected
):

    print()
    print("Confirmed Affected Vulnerabilities")
    print("==================================")

    for index, item in enumerate(
        affected,
        start=1
    ):

        info = extract_cve_information(
            item
        )

        print(
            f"{index}. {info['id']} "
            f"- CVSS {info['cvss_score']}"
        )


def show_unknown_vulnerabilities(
    unknown
):

    print()

    print(
        "Vulnerabilities with UNKNOWN Applicability"
    )

    print(
        "========================================="
    )

    for record in unknown:

        item = record["item"]

        info = extract_cve_information(
            item
        )

        print(
            f" - {info['id']} "
            f"- {record['reason']}"
        )

    print()

    print(
        "These CVEs are not confirmed as affecting "
        "the selected component and are not available "
        "for confirmed-affected selection."
    )


# =========================================================
# CVSS Assessment
# =========================================================

def assess_cvss(info):

    print()
    print("CVSS Assessment")
    print("================")

    print(
        f"CVE: {info['id']}"
    )

    print(
        f"CVSS Version: "
        f"{info['cvss_version']}"
    )

    print(
        f"CVSS Score from NVD: "
        f"{info['cvss_score']}"
    )

    print(
        f"CVSS Vector: "
        f"{info['cvss_vector']}"
    )

    # Our current mathematical
    # implementation supports CVSS 3.0/3.1.

    if (
        info["cvss_vector"]
        and info["cvss_version"]
        in ("3.0", "3.1")
    ):

        result = calculate_cvss(
            info["cvss_vector"]
        )

        print()
        print("CVSS Calculation")
        print("-----------------")

        print(
            f"Exploitability: "
            f"{result['exploitability']:.3f}"
        )

        print(
            f"Impact: "
            f"{result['impact']:.3f}"
        )

        print(
            f"Calculated Base Score: "
            f"{result['base_score']:.1f}"
        )

        return result

    print()

    print(
        "CVSS calculation is not available "
        "for this CVE."
    )

    return None


# =========================================================
# Propagation Assessment
# =========================================================

def assess_propagation(path):

    print()
    print("Propagation Assessment")
    print("======================")

    edge_scores = []
    limitations = []

    for i in range(
        len(path) - 1
    ):

        source = path[i]

        destination = path[i + 1]

        relationship = get_relationship(
            source,
            destination
        )

        print()

        print(
            f"{source} -> {destination}"
        )

        if not isinstance(relationship, dict):

            print(
                "Relationship information "
                "unavailable."
            )

            print(
                "Propagation score: "
                "NOT CALCULATED"
            )

            limitations.append(
                f"{source} -> {destination}: "
                "relationship evidence is unavailable"
            )

            continue

        status = relationship.get(
            "status",
            "UNKNOWN"
        )

        print(
            f"Relationship status: "
            f"{status}"
        )

        print(
            f"Relationship type: "
            f"{relationship.get('relationship_type', 'unknown')}"
        )

        notes = relationship.get("notes")

        if notes:

            print(
                f"Notes: {notes}"
            )

        if status != "SUPPORTED":

            print(
                "Propagation score: "
                "NOT CALCULATED"
            )

            limitations.append(
                f"{source} -> {destination}: "
                f"relationship status is {status}"
            )

            continue

        required_evidence = (
            "reachability",
            "authentication",
            "authorization",
            "dependency"
        )

        missing_evidence = [
            field
            for field in required_evidence
            if field not in relationship
        ]

        if missing_evidence:

            print(
                "Propagation score: "
                "NOT CALCULATED"
            )

            print(
                "Missing scoring evidence: "
                + ", ".join(missing_evidence)
            )

            limitations.append(
                f"{source} -> {destination}: supported "
                "relationship lacks scoring evidence"
            )

            continue

        try:

            score = calculate_propagation_score(
                relationship["reachability"],
                relationship["authentication"],
                relationship["authorization"],
                relationship["dependency"]
            )

        except KeyError:

            print(
                "Propagation score: "
                "NOT CALCULATED"
            )

            limitations.append(
                f"{source} -> {destination}: supported "
                "relationship has unsupported scoring evidence"
            )

            continue

        print(
            f"Propagation Score: "
            f"{score:.4f}"
        )

        edge_scores.append(
            score
        )

    if limitations or not edge_scores:

        if not limitations:

            limitations.append(
                "the path contains no scoreable relationships"
            )

        explanation = "; ".join(
            limitations
        )

        print()

        print(
            "Path Propagation Assessment: "
            "INSUFFICIENT_EVIDENCE"
        )

        print(
            f"Reason: {explanation}"
        )

        return {
            "status": "INSUFFICIENT_EVIDENCE",
            "propagation_score": None,
            "explanation": explanation
        }

    cumulative = calculate_path_propagation(
        edge_scores
    )

    print()

    print(
        f"Cumulative Propagation Potential: "
        f"{cumulative:.6f}"
    )

    return {
        "status": "SUPPORTED",
        "propagation_score": cumulative,
        "explanation": (
            "All relationships are supported and include "
            "the existing propagation-scoring evidence."
        )
    }


# =========================================================
# EBSR Integration
# =========================================================

def build_deployment_assessment(
    selected,
    component_name,
    component_id,
    version,
    retrieval
):
    """Build the deployment-scoped evidence consumed by the EBSR adapter."""

    assessment_groups = retrieval.get(
        "assessments"
    )

    if not assessment_groups:

        assessment_groups = {
            "affected": [],
            "unknown": [],
            "not_affected": []
        }
        provenance = {
            record.get("cve_id"): record
            for record in retrieval.get(
                "applicability",
                []
            )
            if isinstance(record, dict)
        }

        for status_group, items in (
            ("affected", retrieval.get("affected_items", [])),
            ("unknown", [
                record["item"]
                for record in retrieval.get("unknown_items", [])
            ]),
            ("not_affected", retrieval.get(
                "not_affected_items",
                []
            )),
        ):

            for item in items:

                try:
                    info = extract_cve_information(item)
                except (AttributeError, TypeError):
                    continue

                record = provenance.get(
                    info["id"],
                    {}
                )
                assessment_groups[status_group].append({
                    "cve_id": info["id"],
                    "status": record.get(
                        "status",
                        status_group.upper()
                    ),
                    "reason": record.get("reason"),
                    "cvss": cvss_summary(item),
                    "description": info.get(
                        "description",
                        ""
                    )[:200],
                    "applicability": record
                })

    retrieval_summary = {
        "status": retrieval.get("status"),
        "received": retrieval.get("received"),
        "total_results": retrieval.get("total_results"),
        "error": retrieval.get("error")
    }

    return {
        "component": component_name,
        "component_id": component_id,
        "deployment_id": selected.get("deployment_id"),
        "display_name": component_name,
        "version": version,
        "detected_version": selected.get("version"),
        "assessment_version_source": selected.get(
            "version_source"
        ),
        "discovery_evidence": selected.get(
            "discovery_evidence",
            selected
        ),
        "retrieval": retrieval_summary,
        **assessment_groups
    }


def run_ebsr_stage(
    input_document,
    live_assessment,
    output_path=None,
    generated_at=None
):
    """Run and optionally persist the architecture-aware assessment."""

    document = merge_live_assessment(
        input_document or {},
        live_assessment
    )
    report = build_ebsr_assessment(
        document,
        generated_at=generated_at
    )
    print_assessment_summary(report)

    if output_path:

        saved_path = save_assessment(
            report,
            output_path=output_path
        )
        report["saved_path"] = saved_path
        print()
        print(f"Saved EBSR assessment: {saved_path}")

    return report


def run_selected_ebsr(
    selected,
    applicability_component,
    architecture_component,
    version,
    retrieval,
    affected,
    unknown,
    ebsr_input,
    ebsr_output_path
):
    """Run and persist EBSR for every post-retrieval outcome."""

    live_assessment = build_deployment_assessment(
        selected,
        architecture_component,
        applicability_component,
        version,
        {
            **retrieval,
            "affected_items": affected,
            "unknown_items": unknown
        }
    )
    return run_ebsr_stage(
        ebsr_input,
        live_assessment,
        output_path=ebsr_output_path
    )


# =========================================================
# Main Program
# =========================================================

def main(
    ebsr_input=None,
    ebsr_output_path=None
):

    print()
    print("====================================")
    print(" IoMT Risk Assessment")
    print(" NVD + CVSS + Architecture")
    print("====================================")

    show_architecture()


    # =====================================================
    # Automatically Detect Software
    # =====================================================

    software_components = (
        get_available_software()
    )

    print()
    print("Detected Software Components")
    print("=============================")

    if not software_components:

        print(
            "No software with a specific "
            "detected version was found."
        )

        return

    diagnostic_components = {
        component: info
        for component, info in software_components.items()
        if info.get("diagnostic")
    }

    if diagnostic_components:

        print()
        print("Docker Discovery Diagnostics")
        print("============================")

        for component, info in diagnostic_components.items():

            print(f"{component}")
            print(f"  Status: {info.get('status')}")

            if info.get("version"):
                print(f"  Version evidence: {info['version']}")

            if info.get("image"):
                print(f"  Image: {info['image']}")

            if info.get("reason"):
                print(f"  Reason: {info['reason']}")

        print()

    component_names = [
        component
        for component, info in software_components.items()
        if not info.get("diagnostic")
    ]

    if not component_names:

        print(
            "No supported software deployment with a "
            "detected application version was found."
        )

        return

    for index, component in enumerate(
        component_names,
        start=1
    ):

        info = software_components[
            component
        ]

        print(
            f"{index}. {component} "
            f"(version {info['version']})"
        )


    # =====================================================
    # Select Component
    # =====================================================

    choice = input(
        "\nSelect software component: "
    )

    try:

        choice = int(choice)

        target = component_names[
            choice - 1
        ]

    except (
        ValueError,
        IndexError
    ):

        print(
            "Invalid selection."
        )

        return


    selected = software_components[
        target
    ]

    software = selected["software"]

    version = selected["version"]

    applicability_component = (
        selected.get("applicability_component")
        or selected.get("component_id")
        or target
    )

    architecture_component = (
        selected.get("architecture_component")
        or selected.get("component_name")
        or selected.get("display_name")
        or target
    )


    # =====================================================
    # Selected Component
    # =====================================================

    print()
    print("Selected Component")
    print("==================")

    print(
        f"Component: {target}"
    )

    print(
        f"Container: "
        f"{selected['container']}"
    )

    print(
        f"Image: "
        f"{selected['image']}"
    )

    print(
        f"Detected Version: "
        f"{version}"
    )


    # =====================================================
    # NVD
    # =====================================================

    affected, unknown, retrieval = (
        get_vulnerabilities(
            applicability_component,
            software,
            version
        )
    )

    show_retrieval_status(
        retrieval
    )

    if retrieval["status"] in (
        RETRIEVAL_FAILED,
        RETRIEVAL_MALFORMED
    ):

        print()

        print(
            "The NVD retrieval could not be completed "
            "reliably, so vulnerability absence cannot "
            "be inferred."
        )

        run_selected_ebsr(
            selected,
            applicability_component,
            architecture_component,
            version,
            retrieval,
            affected,
            unknown,
            ebsr_input,
            ebsr_output_path
        )
        return

    if (
        retrieval["status"] == RETRIEVAL_COMPLETE
        and retrieval["received"] == 0
    ):

        print()

        print(
            "NVD retrieval completed successfully "
            "but returned no matching CVE records."
        )

        run_selected_ebsr(
            selected,
            applicability_component,
            architecture_component,
            version,
            retrieval,
            affected,
            unknown,
            ebsr_input,
            ebsr_output_path
        )
        return

    if retrieval["received"] == 0:

        print()

        print(
            "No usable CVE records were retrieved. "
            "The overall assessment is incomplete."
        )

        run_selected_ebsr(
            selected,
            applicability_component,
            architecture_component,
            version,
            retrieval,
            affected,
            unknown,
            ebsr_input,
            ebsr_output_path
        )
        return


    # =====================================================
    # No Applicable CVEs
    # =====================================================

    if not affected:

        print()

        print(
            "No retrieved CVE was confirmed as "
            "affecting this software/version."
        )

        if unknown:

            show_unknown_vulnerabilities(
                unknown
            )

        run_selected_ebsr(
            selected,
            applicability_component,
            architecture_component,
            version,
            retrieval,
            affected,
            unknown,
            ebsr_input,
            ebsr_output_path
        )
        return


    # =====================================================
    # Display Applicable CVEs
    # =====================================================

    show_vulnerabilities(
        affected
    )

    if unknown:

        show_unknown_vulnerabilities(
            unknown
        )


    # =====================================================
    # Select Vulnerability
    # =====================================================

    selection = input(
        "\nSelect vulnerability: "
    )

    try:

        selection = int(selection)

        selected_item = affected[
            selection - 1
        ]

    except (
        ValueError,
        IndexError
    ):

        print(
            "Invalid selection."
        )

        return


    # =====================================================
    # CVE Information
    # =====================================================

    info = extract_cve_information(
        selected_item
    )




    # =====================================================
    # CVSS
    # =====================================================

    cvss_result = assess_cvss(
        info
    )


    # =====================================================
    # Attack Path
    # =====================================================

    path = get_attack_path(
        architecture_component
    )

    print()
    print("Potential Attack Path")
    print("=====================")

    print(
        " -> ".join(path)
    )


    # =====================================================
    # Architecture-Aware EBSR Assessment
    # =====================================================

    ebsr_report = run_selected_ebsr(
        selected,
        applicability_component,
        architecture_component,
        version,
        retrieval,
        affected,
        unknown,
        ebsr_input,
        ebsr_output_path
    )


    # =====================================================
    # Summary
    # =====================================================

    print()
    print("Assessment Summary")
    print("==================")

    print(
        f"Component: {target}"
    )

    print(
        f"CVE: {info['id']}"
    )

    print(
        f"Detected Version: {version}"
    )

    print(
        f"CVSS Version: "
        f"{info['cvss_version']}"
    )

    print(
        f"CVSS Score: "
        f"{info['cvss_score']}"
    )

    if cvss_result:

        print(
            f"CVSS Exploitability: "
            f"{cvss_result['exploitability']:.3f}"
        )

        print(
            f"CVSS Impact: "
            f"{cvss_result['impact']:.3f}"
        )

        print(
            f"Calculated Base Score: "
            f"{cvss_result['base_score']:.1f}"
        )

    print(
        f"EBSR scenario results: "
        f"{len(ebsr_report['scenario_results'])}"
    )

    print(
        f"EBSR NOT_ASSESSED CVEs: "
        f"{len(ebsr_report['not_assessed_cves'])}"
    )

    print()

    print(
        "Note: EBSR outputs are evidence-bounded profiles. "
        "They are not exploitation probabilities and do not "
        "establish experimental propagation."
    )


def run_cli(argv=None):
    """Run the interactive workflow or an offline EBSR replay."""

    parser = argparse.ArgumentParser(
        description=(
            "IoMT deployment CVE assessment with EBSR "
            "architecture-aware evidence evaluation."
        )
    )
    parser.add_argument(
        "--ebsr-scenarios",
        help="JSON file containing deployments, attacker profiles, "
             "architecture evidence, CVE assessments and scenarios."
    )
    parser.add_argument(
        "--ebsr-out",
        help="EBSR report file or output directory. A versioned filename "
             "is created when this is a directory."
    )
    parser.add_argument(
        "--ebsr-replay",
        help="Replay a saved EBSR report offline without Docker or NVD."
    )
    args = parser.parse_args(argv)

    if args.ebsr_replay:

        report = replay_assessment(args.ebsr_replay)
        print_assessment_summary(report)
        saved_path = save_assessment(
            report,
            output_path=args.ebsr_out
        )
        print()
        print(f"Saved replayed EBSR assessment: {saved_path}")
        return

    ebsr_input = (
        load_ebsr_input(args.ebsr_scenarios)
        if args.ebsr_scenarios
        else {}
    )
    main(
        ebsr_input=ebsr_input,
        ebsr_output_path=(
            args.ebsr_out
            or "output/ebsr_assessments"
        )
    )


# =========================================================
# Program Entry Point
# =========================================================

if __name__ == "__main__":

    run_cli()
