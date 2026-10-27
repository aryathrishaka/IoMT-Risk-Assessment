# =========================================================
# IoMT Risk Assessment
# NVD -> CVE -> CVSS -> Architecture / Propagation
# =========================================================


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
    search_cves_by_keyword,
    determine_cve_applicability,
    extract_cve_information
)

from cvss_model import calculate_cvss

from version_detector import detect_versions


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
                    software.lower(),

                "version":
                    version,

                "container":
                    info["container"],

                "image":
                    info["image"]
            }

    return available


# =========================================================
# NVD Lookup
# =========================================================

def get_vulnerabilities(
    software,
    version
):

    print()

    print(
        f"Searching NVD for: "
        f"{software} {version}"
    )

    candidates = search_cves_by_keyword(
        software,
        results_per_page=100
    )

    print(
        f"NVD returned "
        f"{len(candidates)} candidate CVE record(s)."
    )

    affected = []
    unknown = []

    for item in candidates:

        status = determine_cve_applicability(
            item,
            software,
            version
        )

        if status == "AFFECTED":

            affected.append(item)

        elif status == "UNKNOWN":

            unknown.append(item)

    return affected, unknown


# =========================================================
# Show CVEs
# =========================================================

def show_vulnerabilities(
    affected
):

    print()
    print("Applicable Vulnerabilities")
    print("===========================")

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

        if relationship is None:

            print(
                "Relationship information "
                "unavailable."
            )

            continue

        print(
            f"Reachability: "
            f"{relationship['reachability']}"
        )

        print(
            f"Authentication: "
            f"{relationship['authentication']}"
        )

        print(
            f"Authorization: "
            f"{relationship['authorization']}"
        )

        print(
            f"Dependency: "
            f"{relationship['dependency']}"
        )

        score = calculate_propagation_score(
            relationship["reachability"],
            relationship["authentication"],
            relationship["authorization"],
            relationship["dependency"]
        )

        print(
            f"Propagation Score: "
            f"{score:.4f}"
        )

        edge_scores.append(
            score
        )

    cumulative = calculate_path_propagation(
        edge_scores
    )

    print()

    print(
        f"Cumulative Propagation Potential: "
        f"{cumulative:.6f}"
    )

    return cumulative


# =========================================================
# Main Program
# =========================================================

def main():

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

    component_names = list(
        software_components.keys()
    )

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

    affected, unknown = (
        get_vulnerabilities(
            software,
            version
        )
    )


    # =====================================================
    # No Applicable CVEs
    # =====================================================

    if not affected:

        print()

        print(
            "No CVE was confirmed as "
            "affecting this software/version."
        )

        if unknown:

            print()

            print(
                "Some candidate CVEs could "
                "not be automatically classified:"
            )

            for item in unknown:

                print(
                    f" - "
                    f"{item['cve']['id']}"
                )

        return


    # =====================================================
    # Display Applicable CVEs
    # =====================================================

    show_vulnerabilities(
        affected
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
        target
    )

    print()
    print("Potential Attack Path")
    print("=====================")

    print(
        " -> ".join(path)
    )


    # =====================================================
    # Propagation
    # =====================================================

    cumulative_propagation = (
        assess_propagation(path)
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
        f"Path Propagation Potential: "
        f"{cumulative_propagation:.6f}"
    )

    print()

    print(
        "Note: propagation scoring is "
        "currently a prototype and requires "
        "research-based validation."
    )


# =========================================================
# Program Entry Point
# =========================================================

if __name__ == "__main__":

    main()