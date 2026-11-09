import requests
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from packaging.version import Version, InvalidVersion
from precondition_analyzer import analyze_preconditions


NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_REQUEST_TIMEOUT = 30
NVD_MAX_ATTEMPTS = 3
NVD_BACKOFF_SECONDS = 1.0
NVD_MAX_RETRY_DELAY = 5.0
NVD_MAX_PAGES = 1000

RETRIEVAL_COMPLETE = "COMPLETE"
RETRIEVAL_PARTIAL = "PARTIAL"
RETRIEVAL_FAILED = "FAILED"
RETRIEVAL_MALFORMED = "MALFORMED"


# ---------------------------------------------------------
# NVD API
# ---------------------------------------------------------

def _retrieval_result(
    status,
    items,
    total_results=None,
    error=None
):
    """Return the small retrieval-status contract used by the CLI."""

    return {
        "status": status,
        "items": items,
        "received": len(items),
        "total_results": total_results,
        "error": error
    }


def _retry_delay(
    response,
    attempt,
    backoff_seconds,
    max_retry_delay
):
    """Calculate a bounded retry delay, honouring Retry-After."""

    retry_after = None

    if response is not None:
        retry_after = response.headers.get("Retry-After")

    if retry_after:
        try:
            delay = float(retry_after)
        except (TypeError, ValueError):
            try:
                retry_time = parsedate_to_datetime(retry_after)
                if retry_time.tzinfo is None:
                    retry_time = retry_time.replace(tzinfo=timezone.utc)
                delay = (
                    retry_time - datetime.now(timezone.utc)
                ).total_seconds()
            except (TypeError, ValueError, OverflowError):
                delay = backoff_seconds * (2 ** attempt)
    else:
        delay = backoff_seconds * (2 ** attempt)

    return max(0.0, min(delay, max_retry_delay))


def _new_nvd_session():
    """Create the direct, verified transport used for one NVD retrieval."""

    session = requests.Session()
    session.trust_env = False
    session.verify = True
    return session


def _request_nvd_page(
    session,
    params,
    max_attempts,
    backoff_seconds,
    max_retry_delay
):
    """Fetch one page with bounded handling of transient failures."""

    last_error = None

    for attempt in range(max_attempts):

        response = None

        try:

            response = session.get(
                NVD_CVE_API,
                params=params,
                timeout=NVD_REQUEST_TIMEOUT,
                verify=True
            )

            response.raise_for_status()

            return response, None

        except requests.HTTPError as error:

            status_code = (
                response.status_code
                if response is not None
                else None
            )

            last_error = (
                f"HTTP {status_code}: {error}"
                if status_code is not None
                else f"HTTP error: {error}"
            )

            retryable = (
                status_code == 429
                or (
                    status_code is not None
                    and 500 <= status_code <= 599
                )
            )

            if not retryable or attempt + 1 >= max_attempts:
                return None, last_error

        except (
            requests.Timeout,
            requests.ConnectionError
        ) as error:

            last_error = (
                f"{type(error).__name__}: {error}"
            )

            if attempt + 1 >= max_attempts:
                return None, last_error

        except requests.RequestException as error:

            return None, (
                f"{type(error).__name__}: {error}"
            )

        time.sleep(
            _retry_delay(
                response,
                attempt,
                backoff_seconds,
                max_retry_delay
            )
        )

    return None, last_error or "NVD request failed."


def _valid_cve_id(item):
    """Return the CVE ID for a minimally valid NVD record."""

    if not isinstance(item, dict):
        return None

    cve = item.get("cve")

    if not isinstance(cve, dict):
        return None

    cve_id = cve.get("id")

    if not isinstance(cve_id, str) or not cve_id.strip():
        return None

    return cve_id


def _invalid_or_partial_result(
    items,
    total_results,
    status_if_empty,
    error,
    partial_if_records=True
):
    """Retain valid records when a response cannot be processed fully."""

    status = (
        RETRIEVAL_PARTIAL
        if items and partial_if_records
        else status_if_empty
    )

    return _retrieval_result(
        status,
        items,
        total_results,
        error
    )


def search_cves_by_keyword_with_status(
    product_name,
    results_per_page=100,
    max_attempts=NVD_MAX_ATTEMPTS,
    backoff_seconds=NVD_BACKOFF_SECONDS,
    max_retry_delay=NVD_MAX_RETRY_DELAY
):
    """Retrieve NVD CVEs using one dedicated Session with explicit closure."""

    with _new_nvd_session() as session:

        return _search_cves_by_keyword_with_status(
            session,
            product_name,
            results_per_page,
            max_attempts,
            backoff_seconds,
            max_retry_delay
        )


def _search_cves_by_keyword_with_status(
    session,
    product_name,
    results_per_page=100,
    max_attempts=NVD_MAX_ATTEMPTS,
    backoff_seconds=NVD_BACKOFF_SECONDS,
    max_retry_delay=NVD_MAX_RETRY_DELAY
):
    """
    Retrieve NVD CVEs with explicit completeness and error status.

    The result contains status, items, received, total_results and error.
    Only unique, minimally valid NVD CVE records are included in items.
    """

    if not isinstance(results_per_page, int) or results_per_page <= 0:
        raise ValueError("results_per_page must be a positive integer.")

    if not isinstance(max_attempts, int) or max_attempts <= 0:
        raise ValueError("max_attempts must be a positive integer.")

    items = []
    seen_ids = set()
    errors = []
    total_results = None
    start_index = 0
    pages_requested = 0

    while True:

        pages_requested += 1

        params = {
            "keywordSearch": product_name,
            "resultsPerPage": results_per_page,
            "startIndex": start_index
        }

        response, request_error = _request_nvd_page(
            session,
            params,
            max_attempts,
            backoff_seconds,
            max_retry_delay
        )

        if response is None:

            return _invalid_or_partial_result(
                items,
                total_results,
                RETRIEVAL_FAILED,
                request_error
            )

        try:

            data = response.json()

        except requests.exceptions.JSONDecodeError as error:

            return _invalid_or_partial_result(
                items,
                total_results,
                RETRIEVAL_MALFORMED,
                f"Invalid JSON from NVD: {error}"
            )

        if not isinstance(data, dict):

            return _invalid_or_partial_result(
                items,
                total_results,
                RETRIEVAL_MALFORMED,
                "NVD response payload is not a JSON object."
            )

        vulnerabilities = data.get("vulnerabilities")

        if not isinstance(vulnerabilities, list):

            return _invalid_or_partial_result(
                items,
                total_results,
                RETRIEVAL_MALFORMED,
                "NVD response has a missing or invalid vulnerabilities collection."
            )

        page_errors = []
        response_total = data.get("totalResults")
        response_start = data.get("startIndex")
        response_page_size = data.get("resultsPerPage")

        if (
            not isinstance(response_total, int)
            or isinstance(response_total, bool)
            or response_total < 0
        ):

            page_errors.append(
                "NVD response has a missing or invalid totalResults value."
            )

        elif total_results is None:

            total_results = response_total

        elif response_total != total_results:

            page_errors.append(
                "NVD totalResults changed during pagination "
                f"({total_results} -> {response_total})."
            )

        if (
            not isinstance(response_start, int)
            or isinstance(response_start, bool)
            or response_start < 0
        ):

            page_errors.append(
                "NVD response has a missing or invalid startIndex value."
            )

        elif response_start != start_index:

            page_errors.append(
                "NVD returned inconsistent pagination metadata "
                f"(requested startIndex {start_index}, "
                f"received {response_start})."
            )

        if (
            not isinstance(response_page_size, int)
            or isinstance(response_page_size, bool)
            or response_page_size < 0
        ):

            page_errors.append(
                "NVD response has a missing or invalid resultsPerPage value."
            )

        new_records = 0
        invalid_records = 0
        duplicate_records = 0

        for item in vulnerabilities:

            cve_id = _valid_cve_id(item)

            if cve_id is None:

                invalid_records += 1
                continue

            if cve_id in seen_ids:

                duplicate_records += 1
                continue

            seen_ids.add(cve_id)
            items.append(item)
            new_records += 1

        if invalid_records:

            page_errors.append(
                f"Ignored {invalid_records} malformed CVE record(s)."
            )

        if duplicate_records:

            page_errors.append(
                f"Ignored {duplicate_records} duplicate CVE record(s)."
            )

        if vulnerabilities and new_records == 0:

            page_errors.append(
                "NVD returned a repeated pagination page with no new CVEs."
            )

        page_count = len(vulnerabilities)

        if (
            page_count == 0
            and total_results is not None
            and start_index < total_results
        ):

            page_errors.append(
                "NVD returned an empty page before totalResults was reached."
            )

        if (
            total_results is not None
            and start_index + page_count > total_results
        ):

            page_errors.append(
                "NVD returned more records than totalResults reports."
            )

        errors.extend(page_errors)
        start_index += page_count

        if page_errors:

            if items:

                return _retrieval_result(
                    RETRIEVAL_PARTIAL,
                    items,
                    total_results,
                    "; ".join(dict.fromkeys(errors))
                )

            if (
                total_results is not None
                and page_count == 0
                and total_results > 0
            ):

                return _retrieval_result(
                    RETRIEVAL_PARTIAL,
                    items,
                    total_results,
                    "; ".join(dict.fromkeys(errors))
                )

            return _retrieval_result(
                RETRIEVAL_MALFORMED,
                items,
                total_results,
                "; ".join(dict.fromkeys(errors))
            )

        if page_count == 0:

            break

        if total_results is None:

            errors.append(
                "NVD pagination completeness cannot be established."
            )

            break

        if start_index >= total_results:

            break

        if pages_requested >= NVD_MAX_PAGES:

            errors.append(
                f"NVD pagination exceeded {NVD_MAX_PAGES} pages."
            )

            break

    if errors:

        return _retrieval_result(
            RETRIEVAL_PARTIAL,
            items,
            total_results,
            "; ".join(dict.fromkeys(errors))
        )

    if total_results is None or len(items) != total_results:

        return _retrieval_result(
            RETRIEVAL_PARTIAL,
            items,
            total_results,
            "Unique valid records do not match NVD totalResults."
        )

    return _retrieval_result(
        RETRIEVAL_COMPLETE,
        items,
        total_results
    )


def search_cves_by_keyword(product_name, results_per_page=100):
    """
    Retrieve CVE records using the legacy list-returning interface.

    Callers using this wrapper cannot distinguish complete, partial or
    failed retrieval. The main workflow uses the status-aware interface.
    """

    result = search_cves_by_keyword_with_status(
        product_name,
        results_per_page
    )

    return result["items"]


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

