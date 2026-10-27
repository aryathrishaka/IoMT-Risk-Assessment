import requests
from packaging.version import Version, InvalidVersion
from precondition_analyzer import analyze_preconditions


NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ---------------------------------------------------------
# NVD API
# ---------------------------------------------------------

def search_cves_by_keyword(product_name, results_per_page=100):
    """
    Retrieve CVE records from NVD using a product keyword.
    """

    all_results = []
    start_index = 0

    while True:

        params = {
            "keywordSearch": product_name,
            "resultsPerPage": results_per_page,
            "startIndex": start_index
        }

        try:
            response = requests.get(
                NVD_CVE_API,
                params=params,
                timeout=30
            )

            response.raise_for_status()

            data = response.json()

        except requests.RequestException as error:
            print(f"NVD API error: {error}")
            return all_results

        vulnerabilities = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)

        all_results.extend(vulnerabilities)

        start_index += len(vulnerabilities)

        if start_index >= total_results or not vulnerabilities:
            break

    return all_results


# ---------------------------------------------------------
# Version comparison
# ---------------------------------------------------------

def compare_versions(version_a, version_b):
    """
    Compare two software versions.

    Returns:
        -1 if A < B
         0 if A == B
         1 if A > B
        None if comparison is not possible
    """

    try:
        a = Version(version_a)
        b = Version(version_b)

        if a < b:
            return -1

        if a > b:
            return 1

        return 0

    except InvalidVersion:
        return None


def version_matches_range(
    version,
    start_including=None,
    start_excluding=None,
    end_including=None,
    end_excluding=None
):
    """
    Check whether a version falls inside an NVD version range.
    """

    try:
        current = Version(version)

        if start_including:
            if current < Version(start_including):
                return False

        if start_excluding:
            if current <= Version(start_excluding):
                return False

        if end_including:
            if current > Version(end_including):
                return False

        if end_excluding:
            if current >= Version(end_excluding):
                return False

        return True

    except InvalidVersion:
        return None


# ---------------------------------------------------------
# Product matching
# ---------------------------------------------------------

def cpe_product_matches(cpe_name, product_name):
    """
    Check whether a CPE refers to the selected product.

    Example:
    cpe:2.3:a:eclipse:mosquitto:*:*:*:*:*:*:*:*
    """

    parts = cpe_name.split(":")

    if len(parts) < 6:
        return False

    cpe_product = parts[4].lower().replace("_", " ")

    selected_product = product_name.lower().replace("_", " ")

    return (
        cpe_product == selected_product
        or selected_product in cpe_product
        or cpe_product in selected_product
    )


# ---------------------------------------------------------
# CPE configuration evaluation
# ---------------------------------------------------------

def evaluate_cpe_match(
    cpe_match,
    product_name,
    version
):
    """
    Evaluate one NVD cpeMatch entry.

    Returns:
        AFFECTED
        NOT_AFFECTED
        UNKNOWN
        IRRELEVANT
    """

    if not cpe_match.get("vulnerable", False):
        return "IRRELEVANT"

    cpe_name = cpe_match.get("criteria", "")

    if not cpe_product_matches(
        cpe_name,
        product_name
    ):
        return "IRRELEVANT"

    parts = cpe_name.split(":")

    if len(parts) < 6:
        return "UNKNOWN"

    cpe_version = parts[5]

    # -----------------------------------------
    # Exact CPE version
    # -----------------------------------------

    if cpe_version not in ("*", "-"):

        comparison = compare_versions(
            version,
            cpe_version
        )

        if comparison is None:
            return "UNKNOWN"

        if comparison == 0:
            return "AFFECTED"

        return "NOT_AFFECTED"

    # -----------------------------------------
    # Version range
    # -----------------------------------------

    result = version_matches_range(
        version,
        cpe_match.get("versionStartIncluding"),
        cpe_match.get("versionStartExcluding"),
        cpe_match.get("versionEndIncluding"),
        cpe_match.get("versionEndExcluding")
    )

    if result is None:
        return "UNKNOWN"

    if result:
        return "AFFECTED"

    return "NOT_AFFECTED"


def evaluate_configuration_node(
    node,
    product_name,
    version
):
    """
    Recursively evaluate an NVD configuration node.

    Supports OR / AND structures.

    Returns:
        AFFECTED
        NOT_AFFECTED
        UNKNOWN
        IRRELEVANT
    """

    operator = node.get("operator", "OR").upper()

    results = []

    # -----------------------------------------
    # Evaluate direct CPE matches
    # -----------------------------------------

    for cpe_match in node.get("cpeMatch", []):

        result = evaluate_cpe_match(
            cpe_match,
            product_name,
            version
        )

        if result != "IRRELEVANT":
            results.append(result)

    # -----------------------------------------
    # Evaluate child nodes recursively
    # -----------------------------------------

    for child in node.get("nodes", []):

        result = evaluate_configuration_node(
            child,
            product_name,
            version
        )

        if result != "IRRELEVANT":
            results.append(result)

    if not results:
        return "IRRELEVANT"

    # -----------------------------------------
    # OR logic
    # -----------------------------------------

    if operator == "OR":

        if "AFFECTED" in results:
            return "AFFECTED"

        if all(
            result == "NOT_AFFECTED"
            for result in results
        ):
            return "NOT_AFFECTED"

        return "UNKNOWN"

    # -----------------------------------------
    # AND logic
    # -----------------------------------------

    if operator == "AND":

        if "NOT_AFFECTED" in results:
            return "NOT_AFFECTED"

        if all(
            result == "AFFECTED"
            for result in results
        ):
            return "AFFECTED"

        return "UNKNOWN"

    return "UNKNOWN"


# ---------------------------------------------------------
# Modern "affected" data
# ---------------------------------------------------------

def check_modern_affected_data(
    cve,
    product_name,
    version
):
    """
    Check structured affected-product information
    when available in the CVE record.
    """

    containers = cve.get("containers", {})
    cna = containers.get("cna", {})

    affected_entries = cna.get("affected", [])

    if not affected_entries:
        return "IRRELEVANT"

    found_product = False
    unknown = False

    for entry in affected_entries:

        entry_product = str(
            entry.get("product", "")
        ).lower()

        entry_vendor = str(
            entry.get("vendor", "")
        ).lower()

        selected = product_name.lower()

        if (
            selected not in entry_product
            and selected not in entry_vendor
        ):
            continue

        found_product = True

        versions = entry.get("versions", [])

        if not versions:
            return "UNKNOWN"

        for version_entry in versions:

            status = str(
                version_entry.get("status", "")
            ).lower()

            affected_status = status == "affected"

            if not affected_status:
                continue

            exact_version = version_entry.get(
                "version"
            )

            less_than = version_entry.get(
                "lessThan"
            )

            less_than_or_equal = version_entry.get(
                "lessThanOrEqual"
            )

            # Exact version
            if exact_version:

                if version == exact_version:
                    return "AFFECTED"

            # Version range using lessThan
            if less_than:

                try:
                    if Version(version) < Version(
                        less_than
                    ):
                        return "AFFECTED"

                except InvalidVersion:
                    unknown = True

            # Version range using lessThanOrEqual
            if less_than_or_equal:

                try:
                    if Version(version) <= Version(
                        less_than_or_equal
                    ):
                        return "AFFECTED"

                except InvalidVersion:
                    unknown = True

            # Range text such as:
            # >= 2.0.0, < 2.1.0
            range_text = version_entry.get(
                "range"
            )

            if range_text:

                if evaluate_range_text(
                    version,
                    range_text
                ):
                    return "AFFECTED"

                unknown = True

    if found_product and unknown:
        return "UNKNOWN"

    if found_product:
        return "NOT_AFFECTED"

    return "IRRELEVANT"


def evaluate_range_text(version, range_text):
    """
    Evaluate simple range expressions such as:

        >= 2.0.0, < 2.1.0
        > 1.0.0
        <= 2.0.18
    """

    try:
        current = Version(version)

        conditions = [
            condition.strip()
            for condition in range_text.split(",")
        ]

        for condition in conditions:

            if condition.startswith(">="):
                if current < Version(
                    condition[2:].strip()
                ):
                    return False

            elif condition.startswith("<="):
                if current > Version(
                    condition[2:].strip()
                ):
                    return False

            elif condition.startswith(">"):
                if current <= Version(
                    condition[1:].strip()
                ):
                    return False

            elif condition.startswith("<"):
                if current >= Version(
                    condition[1:].strip()
                ):
                    return False

            elif condition.startswith("="):
                if current != Version(
                    condition[1:].strip()
                ):
                    return False

            else:
                return False

        return True

    except InvalidVersion:
        return False


# ---------------------------------------------------------
# Final applicability decision
# ---------------------------------------------------------

def determine_cve_applicability(
    cve_item,
    product_name,
    version
):
    """
    Determine whether a CVE applies to a product/version.

    Returns:
        AFFECTED
        NOT_AFFECTED
        UNKNOWN
    """

    cve = cve_item.get("cve", {})

    # First check modern affected-product data
    modern_result = check_modern_affected_data(
        cve,
        product_name,
        version
    )

    if modern_result != "IRRELEVANT":
        return modern_result

    # Then check NVD CPE configurations
    configurations = cve.get(
        "configurations",
        []
    )

    found_relevant_configuration = False
    unknown_found = False

    for configuration in configurations:

        result = evaluate_configuration_node(
            configuration,
            product_name,
            version
        )

        if result == "AFFECTED":
            return "AFFECTED"

        if result == "UNKNOWN":
            unknown_found = True

        if result in (
            "NOT_AFFECTED",
            "UNKNOWN"
        ):
            found_relevant_configuration = True

    if unknown_found:
        return "UNKNOWN"

    if found_relevant_configuration:
        return "NOT_AFFECTED"

    return "NOT_AFFECTED"


# ---------------------------------------------------------
# CVSS extraction
# ---------------------------------------------------------

def extract_cve_information(cve_item):
    """
    Extract CVE and CVSS information.
    """

    cve = cve_item.get("cve", {})

    cve_id = cve.get(
        "id",
        "Unknown"
    )

    description = "No description available."

    for desc in cve.get(
        "descriptions",
        []
    ):

        if desc.get("lang") == "en":
            description = desc.get(
                "value",
                description
            )
            break

    cvss_version = None
    cvss_score = None
    cvss_vector = None

    metrics = cve.get(
        "metrics",
        {}
    )

    # CVSS 3.1
    if metrics.get("cvssMetricV31"):

        data = metrics[
            "cvssMetricV31"
        ][0].get(
            "cvssData",
            {}
        )

        cvss_version = "3.1"
        cvss_score = data.get(
            "baseScore"
        )
        cvss_vector = data.get(
            "vectorString"
        )

    # CVSS 3.0
    elif metrics.get("cvssMetricV30"):

        data = metrics[
            "cvssMetricV30"
        ][0].get(
            "cvssData",
            {}
        )

        cvss_version = "3.0"
        cvss_score = data.get(
            "baseScore"
        )
        cvss_vector = data.get(
            "vectorString"
        )

    # CVSS 4.0 is reported but not
    # currently fed into our CVSS-3
    # risk calculation.
    elif metrics.get("cvssMetricV40"):

        data = metrics[
            "cvssMetricV40"
        ][0].get(
            "cvssData",
            {}
        )

        cvss_version = "4.0"
        cvss_score = data.get(
            "baseScore"
        )
        cvss_vector = data.get(
            "vectorString"
        )

    return {
        "id": cve_id,
        "description": description,
        "cvss_version": cvss_version,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector
    }


# ---------------------------------------------------------
# Test
# ---------------------------------------------------------

if __name__ == "__main__":

    print()
    print("NVD Vulnerability Lookup")
    print("========================")
    print()

    software = input(
        "Enter software/product name: "
    ).strip()

    version = input(
        "Enter software version: "
    ).strip()

    print()
    print(
        f"Searching NVD for: "
        f"{software} {version}"
    )
    print()

    candidates = search_cves_by_keyword(
        software,
        results_per_page=100
    )

    print(
        f"NVD returned "
        f"{len(candidates)} candidate CVE record(s)."
    )

    print()
    print(
        "Checking NVD applicability data..."
    )
    print()

    # -----------------------------------------
    # CVE classification containers
    # -----------------------------------------

    affected = []
    unknown = []

    test_candidates = []
    not_ready = []
    manual_review = []

    # -----------------------------------------
    # Check every NVD candidate
    # -----------------------------------------

    for item in candidates:

        status = determine_cve_applicability(
            item,
            software,
            version
        )

        if status == "AFFECTED":

            affected.append(item)

            screening = analyze_preconditions(
                item
            )

            decision = screening["decision"]

            if decision == "TEST CANDIDATE":

                test_candidates.append(
                    (item, screening)
                )

            elif decision == "NOT READY":

                not_ready.append(
                    (item, screening)
                )

            else:

                manual_review.append(
                    (item, screening)
                )

        elif status == "UNKNOWN":

            unknown.append(item)

    # -----------------------------------------
    # Affected CVEs
    # -----------------------------------------

    print(
        f"Confirmed affected CVEs: "
        f"{len(affected)}"
    )

    print()

    for number, item in enumerate(
        affected,
        start=1
    ):

        info = extract_cve_information(
            item
        )

        print(
            f"{number}. {info['id']}"
        )

        print(
            f"   CVSS Version : "
            f"{info['cvss_version']}"
        )

        print(
            f"   CVSS Score   : "
            f"{info['cvss_score']}"
        )

        print(
            f"   CVSS Vector  : "
            f"{info['cvss_vector']}"
        )

        print()

    # -----------------------------------------
    # Precondition & Environment Screening
    # -----------------------------------------

    print(
        "Precondition & Environment Screening"
    )

    print(
        "------------------------------------"
    )

    print()

    for number, (item, screening) in enumerate(
        test_candidates,
        start=1
    ):

        info = extract_cve_information(
            item
        )

        print(
            f"{number}. {info['id']}"
        )

        print(
            f"   Decision             : "
            f"{screening['decision']}"
        )

        print(
            f"   Detected conditions  : "
            f"{', '.join(screening['detected_conditions'])}"
        )

        print(
            f"   Attack Vector        : "
            f"{screening['attack_vector']}"
        )

        print(
            f"   Privileges Required  : "
            f"{screening['privileges_required']}"
        )

        print(
            f"   User Interaction     : "
            f"{screening['user_interaction']}"
        )

        print()

    print(
        f"Test candidates : "
        f"{len(test_candidates)}"
    )

    print(
        f"Not ready       : "
        f"{len(not_ready)}"
    )

    print(
        f"Manual review   : "
        f"{len(manual_review)}"
    )

    print()

    # -----------------------------------------
    # Unknown CVEs
    # -----------------------------------------

    if unknown:

        print(
            "Applicability could not be "
            "determined automatically for:"
        )

        for item in unknown:

            print(
                f"   - "
                f"{item.get('cve', {}).get('id')}"
            )

        print()

    # -----------------------------------------
    # Final interpretation
    # -----------------------------------------

    if not affected and not unknown:

        print(
            f"No NVD vulnerability record "
            f"was identified as affecting "
            f"{software} {version}."
        )

    elif not affected and unknown:

        print(
            "No CVE was confirmed as affected, "
            "but some records require manual "
            "applicability verification."
        )

    print()
    