import re
from typing import Any, Dict, List


# =========================================================
# GENERIC ENVIRONMENT PROFILE
# =========================================================
# This represents the current controlled test environment.
# The structure is reusable across different components.
# =========================================================

ENVIRONMENT = {
    "network_access": True,
    "authentication": True,
    "authorization": True,
    "service_exposure": True,
    "configuration": True,
    "local_access": False,
    "user_interaction": False,

    "feature": {
        "retained_messaging": True
    },

    "security_control": {
        "tls": False
    },

    "privilege": "low",
}


# =========================================================
# GENERIC PREREQUISITE CATEGORIES
# =========================================================

PREREQUISITE_CATEGORIES = {
    "network_access": "Network accessibility",
    "authentication": "Authentication requirement",
    "authorization": "Authorization / access control",
    "service_exposure": "Required service exposure",
    "configuration": "Specific configuration requirement",
    "privilege": "Required privilege level",
    "feature": "Required software feature or state",
    "data_access": "Required data or functionality",
    "dependency": "Required component or service dependency",
    "security_control": "Security-control condition",
    "local_access": "Local access requirement",
    "user_interaction": "User interaction requirement",
}


# =========================================================
# CVSS INFORMATION
# =========================================================

def get_description(cve_record: Dict[str, Any]) -> str:
    """Extract the English CVE description."""

    cve = cve_record.get("cve", {})
    descriptions = cve.get("descriptions", [])

    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "").strip()

    if descriptions:
        return descriptions[0].get("value", "").strip()

    return ""


def get_cvss_vector(cve_record: Dict[str, Any]) -> str:
    """Extract the first available CVSS vector."""

    cve = cve_record.get("cve", {})
    metrics = cve.get("metrics", {})

    for metric_name in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30"
    ):
        metric_list = metrics.get(metric_name, [])

        if metric_list:
            cvss_data = metric_list[0].get(
                "cvssData",
                {}
            )

            return cvss_data.get(
                "vectorString",
                ""
            )

    return ""


def extract_cvss_metric(
    vector: str,
    metric: str
) -> str | None:
    """Extract AV, PR, UI, etc. from a CVSS vector."""

    if not vector:
        return None

    match = re.search(
        rf"(?:^|/){re.escape(metric)}:([^/]+)",
        vector
    )

    if match:
        return match.group(1)

    return None


# =========================================================
# GENERIC PREREQUISITE EXTRACTION
# =========================================================
#
# IMPORTANT:
# This function does NOT use the CVE ID to identify
# prerequisites.
#
# It examines the actual NVD description and CVSS
# information and extracts only conditions for which
# there is recognizable evidence.
#
# If sufficient evidence is not available, the CVE
# remains suitable for MANUAL REVIEW.
# =========================================================

def extract_prerequisites(
    cve_record: Dict[str, Any]
) -> Dict[str, Any]:

    description = get_description(
        cve_record
    )

    description_lower = description.lower()

    vector = get_cvss_vector(
        cve_record
    )

    requirements = {}

    detected_conditions = []

    evidence = []

    # -----------------------------------------------------
    # Network access
    # -----------------------------------------------------

    attack_vector = extract_cvss_metric(
        vector,
        "AV"
    )

    if attack_vector == "N":

        requirements["network_access"] = True

        detected_conditions.append(
            "Network access required"
        )

        evidence.append(
            "CVSS Attack Vector is Network (AV:N)."
        )

    elif attack_vector == "L":

        requirements["local_access"] = True

        detected_conditions.append(
            "Local access required"
        )

        evidence.append(
            "CVSS Attack Vector is Local (AV:L)."
        )

    elif attack_vector == "P":

        requirements["physical_access"] = True

        detected_conditions.append(
            "Physical access required"
        )

        evidence.append(
            "CVSS Attack Vector is Physical (AV:P)."
        )

    # -----------------------------------------------------
    # Privileges
    # -----------------------------------------------------

    privileges = extract_cvss_metric(
        vector,
        "PR"
    )

    if privileges in ("L", "H"):

        requirements["privilege"] = privileges

        detected_conditions.append(
            f"Privileges required: {privileges}"
        )

        evidence.append(
            f"CVSS Privileges Required is {privileges}."
        )

    elif privileges == "N":

        evidence.append(
            "CVSS indicates no privileges are required."
        )

    # -----------------------------------------------------
    # User interaction
    # -----------------------------------------------------

    user_interaction = extract_cvss_metric(
        vector,
        "UI"
    )

    if user_interaction == "R":

        requirements["user_interaction"] = True

        detected_conditions.append(
            "User interaction required"
        )

        evidence.append(
            "CVSS User Interaction is Required (UI:R)."
        )

    elif user_interaction == "N":

        evidence.append(
            "CVSS indicates no user interaction is required."
        )

    # -----------------------------------------------------
    # Retained messaging / retained messages
    # -----------------------------------------------------

    retained_patterns = [
        "retained message",
        "retained messages",
        "retained messaging",
        "mqtt retain",
        "retain flag",
        "retain message"
    ]

    if any(
        pattern in description_lower
        for pattern in retained_patterns
    ):

        requirements.setdefault(
            "feature",
            {}
        )

        requirements["feature"][
            "retained_messaging"
        ] = True

        detected_conditions.append(
            "Retained messaging enabled"
        )

        evidence.append(
            "NVD description references MQTT retained-message functionality."
        )

    # -----------------------------------------------------
    # ACL / access control / authorization
    # -----------------------------------------------------

    authorization_patterns = [
        "access control",
        "access-control",
        "acl",
        "authorization",
        "authorized",
        "permission"
    ]

    if any(
        pattern in description_lower
        for pattern in authorization_patterns
    ):

        requirements[
            "authorization"
        ] = True

        requirements.setdefault(
            "configuration",
            {}
        )

        requirements["configuration"][
            "acl"
        ] = True

        detected_conditions.append(
            "ACL / access control required"
        )

        evidence.append(
            "NVD description references access-control or authorization functionality."
        )

    # -----------------------------------------------------
    # Authentication
    # -----------------------------------------------------

    authentication_patterns = [
        "authentication",
        "authenticated user",
        "authenticated client",
        "login",
        "credentials"
    ]

    if any(
        pattern in description_lower
        for pattern in authentication_patterns
    ):

        requirements[
            "authentication"
        ] = True

        detected_conditions.append(
            "Authentication required"
        )

        evidence.append(
            "NVD description references authentication or credentials."
        )

    # -----------------------------------------------------
    # TLS / security-control condition
    # -----------------------------------------------------

    tls_patterns = [
        "tls",
        "ssl",
        "transport layer security"
    ]

    if any(
        pattern in description_lower
        for pattern in tls_patterns
    ):

        requirements.setdefault(
            "security_control",
            {}
        )

        requirements["security_control"][
            "tls"
        ] = True

        detected_conditions.append(
            "TLS / SSL configuration relevant"
        )

        evidence.append(
            "NVD description references TLS/SSL."
        )

    # -----------------------------------------------------
    # Service exposure
    # -----------------------------------------------------

    service_patterns = [
        "network service",
        "remote service",
        "mqtt service",
        "broker",
        "listening port",
        "service exposed"
    ]

    if any(
        pattern in description_lower
        for pattern in service_patterns
    ):

        requirements[
            "service_exposure"
        ] = True

        detected_conditions.append(
            "Network service exposure"
        )

        evidence.append(
            "NVD description references a network-facing service."
        )

    # -----------------------------------------------------
    # Dependency indicators
    # -----------------------------------------------------

    dependency_patterns = [
        "dependency",
        "dependent component",
        "third-party library",
        "library",
        "plugin"
    ]

    if any(
        pattern in description_lower
        for pattern in dependency_patterns
    ):

        requirements[
            "dependency"
        ] = True

        detected_conditions.append(
            "Dependency or external component involved"
        )

        evidence.append(
            "NVD description references a dependency or external component."
        )

    return {
        "requirements": requirements,
        "detected_conditions": detected_conditions,
        "evidence": evidence
    }


# =========================================================
# ENVIRONMENT CHECKING
# =========================================================

def check_requirements(
    requirements: Dict[str, Any]
) -> Dict[str, Any]:

    result = {}

    for category, requirement in requirements.items():

        # -------------------------------------------------
        # Boolean environment conditions
        # -------------------------------------------------

        if category in (
            "network_access",
            "authentication",
            "authorization",
            "service_exposure",
            "configuration",
            "local_access",
            "user_interaction",
            "data_access",
            "dependency",
            "physical_access"
        ):

            environment_value = ENVIRONMENT.get(
                category
            )

            if environment_value is True:

                result[category] = "PRESENT"

            elif environment_value is False:

                result[category] = "ABSENT"

            else:

                result[category] = "UNKNOWN"

        # -------------------------------------------------
        # Feature requirements
        # -------------------------------------------------

        elif category == "feature":

            feature_results = {}

            environment_features = ENVIRONMENT.get(
                "feature",
                {}
            )

            for feature_name in requirement:

                actual = environment_features.get(
                    feature_name
                )

                if actual is True:

                    feature_results[
                        feature_name
                    ] = "PRESENT"

                elif actual is False:

                    feature_results[
                        feature_name
                    ] = "ABSENT"

                else:

                    feature_results[
                        feature_name
                    ] = "UNKNOWN"

            result[category] = feature_results

        # -------------------------------------------------
        # Configuration requirements
        # -------------------------------------------------

        elif category == "configuration":

            configuration_results = {}

            for config_name in requirement:

                # ACL is represented by the current
                # authorization state.
                if config_name == "acl":

                    actual = ENVIRONMENT.get(
                        "authorization"
                    )

                else:

                    actual = None

                if actual is True:

                    configuration_results[
                        config_name
                    ] = "PRESENT"

                elif actual is False:

                    configuration_results[
                        config_name
                    ] = "ABSENT"

                else:

                    configuration_results[
                        config_name
                    ] = "UNKNOWN"

            result[
                category
            ] = configuration_results

        # -------------------------------------------------
        # Privilege requirement
        # -------------------------------------------------

        elif category == "privilege":

            actual = ENVIRONMENT.get(
                "privilege"
            )

            if actual is None:

                result[
                    category
                ] = "UNKNOWN"

            else:

                # CVSS:
                # N = None
                # L = Low
                # H = High
                #
                # Current environment is represented
                # as "low".

                if requirement == "L":

                    if actual in ("low", "medium", "high"):

                        result[
                            category
                        ] = "PRESENT"

                    else:

                        result[
                            category
                        ] = "UNKNOWN"

                elif requirement == "H":

                    if actual == "high":

                        result[
                            category
                        ] = "PRESENT"

                    else:

                        result[
                            category
                        ] = "ABSENT"

                else:

                    result[
                        category
                    ] = "UNKNOWN"

        # -------------------------------------------------
        # Security controls
        # -------------------------------------------------

        elif category == "security_control":

            security_results = {}

            controls = ENVIRONMENT.get(
                "security_control",
                {}
            )

            for control_name in requirement:

                actual = controls.get(
                    control_name
                )

                if actual is True:

                    security_results[
                        control_name
                    ] = "PRESENT"

                elif actual is False:

                    security_results[
                        control_name
                    ] = "ABSENT"

                else:

                    security_results[
                        control_name
                    ] = "UNKNOWN"

            result[
                category
            ] = security_results

        else:

            result[
                category
            ] = "UNKNOWN"

    return result


# =========================================================
# FLATTEN ENVIRONMENT RESULTS
# =========================================================

def flatten_status(
    result: Dict[str, Any]
) -> List[str]:

    statuses = []

    for value in result.values():

        if isinstance(value, dict):

            for sub_value in value.values():

                statuses.append(
                    sub_value
                )

        else:

            statuses.append(
                value
            )

    return statuses


# =========================================================
# MAIN ANALYSIS
# =========================================================

def analyze_preconditions(
    cve_record: Dict[str, Any]
) -> Dict[str, Any]:

    cve = cve_record.get(
        "cve",
        {}
    )

    cve_id = cve.get(
        "id",
        ""
    )

    description = get_description(
        cve_record
    )

    vector = get_cvss_vector(
        cve_record
    )

    # -----------------------------------------------------
    # Extract conditions from the actual NVD record
    # -----------------------------------------------------

    extraction = extract_prerequisites(
        cve_record
    )

    requirements = extraction[
        "requirements"
    ]

    detected_conditions = extraction[
        "detected_conditions"
    ]

    evidence = extraction[
        "evidence"
    ]

    # -----------------------------------------------------
    # Compare detected requirements against environment
    # -----------------------------------------------------

    environment_check = check_requirements(
        requirements
    )

    statuses = flatten_status(
        environment_check
    )

    # -----------------------------------------------------
    # CVSS information
    # -----------------------------------------------------

    attack_vector = extract_cvss_metric(
        vector,
        "AV"
    )

    privileges = extract_cvss_metric(
        vector,
        "PR"
    )

    user_interaction = extract_cvss_metric(
        vector,
        "UI"
    )

    # -----------------------------------------------------
    # Decision logic
    # -----------------------------------------------------

    if not requirements:

        decision = "MANUAL REVIEW"

        reason = (
            "No sufficiently supported prerequisite "
            "condition could be extracted automatically "
            "from the NVD record."
        )

    elif "ABSENT" in statuses:

        decision = "NOT READY"

        reason = (
            "One or more detected prerequisite "
            "conditions are absent from the current "
            "test environment."
        )

    elif "UNKNOWN" in statuses:

        decision = "MANUAL REVIEW"

        reason = (
            "One or more detected prerequisite "
            "conditions could not be determined "
            "from the current environment."
        )

    else:

        # CVSS-derived conditions such as AV:N, PR:N,
        # and UI:N provide contextual information but
        # are not sufficient by themselves to establish
        # a reproducible test configuration.

        explicit_conditions = []

        if "feature" in requirements:
            explicit_conditions.append(
                "feature"
            )

        if "configuration" in requirements:
            explicit_conditions.append(
                "configuration"
            )

        if "authentication" in requirements:
            explicit_conditions.append(
                "authentication"
            )

        if "authorization" in requirements:
            explicit_conditions.append(
                "authorization"
            )

        if "security_control" in requirements:
            explicit_conditions.append(
                "security_control"
            )

        if "dependency" in requirements:
            explicit_conditions.append(
                "dependency"
            )

        if "data_access" in requirements:
            explicit_conditions.append(
                "data_access"
            )

        if explicit_conditions:

            decision = "TEST CANDIDATE"

            reason = (
                "Explicit prerequisite conditions were "
                "identified from the NVD record and are "
                "satisfied by the current environment."
            )

        else:

            decision = "MANUAL REVIEW"

            reason = (
                "Only contextual CVSS conditions were "
                "identified; additional prerequisite "
                "evidence is required before controlled "
                "validation."
            )

    # -----------------------------------------------------
    # Final structured result
    # -----------------------------------------------------

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_vector": vector,

        "attack_vector": attack_vector,
        "privileges_required": privileges,
        "user_interaction": user_interaction,

        "prerequisite_categories": requirements,
        "detected_conditions": detected_conditions,
        "evidence": evidence,

        "environment_check": environment_check,

        "decision": decision,
        "decision_reason": reason,
    }

# =========================================================
# STANDALONE TEST
# =========================================================

if __name__ == "__main__":

    print()
    print(
        "Generalized CVE Preconditions & Environment Screening"
    )
    print(
        "====================================================="
    )
    print()

    print("Generic Environment:")

    for key, value in ENVIRONMENT.items():

        print(
            f"  {key}: {value}"
        )

    print()
    print(
        "Module ready."
    )
    print(
        "This module performs preliminary screening, "
        "not final exploit confirmation."
    )