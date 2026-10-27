# Risk Model
# CVSS v3.0 + Architecture-aware propagation prototype

import math


def roundup(value):
    """CVSS Roundup function."""
    return math.ceil(value * 10) / 10


# ---------------------------------------------------------
# CVSS v3.0 metric values
# ---------------------------------------------------------

AV_VALUES = {
    "N": 0.85,   # Network
    "A": 0.62,   # Adjacent
    "L": 0.55,   # Local
    "P": 0.20    # Physical
}

AC_VALUES = {
    "L": 0.77,   # Low
    "H": 0.44    # High
}

PR_VALUES_UNCHANGED = {
    "N": 0.85,
    "L": 0.62,
    "H": 0.27
}

PR_VALUES_CHANGED = {
    "N": 0.85,
    "L": 0.68,
    "H": 0.50
}

UI_VALUES = {
    "N": 0.85,
    "R": 0.62
}

CIA_VALUES = {
    "N": 0.00,   # None
    "L": 0.22,   # Low
    "H": 0.56    # High
}


# ---------------------------------------------------------
# Parse CVSS v3.0 vector
# ---------------------------------------------------------

def parse_cvss_vector(vector):
    """
    Extract CVSS v3.0 Base metrics from a vector.
    """

    parts = vector.split("/")

    metrics = {}

    for part in parts:
        if ":" not in part:
            continue

        key, value = part.split(":")
        metrics[key] = value

    return metrics


# ---------------------------------------------------------
# CVSS v3.0 calculations
# ---------------------------------------------------------

def calculate_cvss(vector):
    """
    Calculate CVSS v3.0 Base Score from the CVSS vector.
    """

    m = parse_cvss_vector(vector)

    av = AV_VALUES[m["AV"]]
    ac = AC_VALUES[m["AC"]]

    if m["S"] == "U":
        pr = PR_VALUES_UNCHANGED[m["PR"]]
    else:
        pr = PR_VALUES_CHANGED[m["PR"]]

    ui = UI_VALUES[m["UI"]]

    c = CIA_VALUES[m["C"]]
    i = CIA_VALUES[m["I"]]
    a = CIA_VALUES[m["A"]]

    # Exploitability sub-score
    exploitability = (
        8.22
        * av
        * ac
        * pr
        * ui
    )

    # Impact Subscore
    isc_base = (
        1
        - (1 - c)
        * (1 - i)
        * (1 - a)
    )

    if m["S"] == "U":

        impact = 6.42 * isc_base

        if impact <= 0:
            base_score = 0.0
        else:
            base_score = roundup(
                min(impact + exploitability, 10)
            )

    else:

        impact = (
            7.52 * (isc_base - 0.029)
            - 3.25 * ((isc_base - 0.02) ** 15)
        )

        if impact <= 0:
            base_score = 0.0
        else:
            base_score = roundup(
                min(
                    1.08 * (impact + exploitability),
                    10
                )
            )

    return {
        "exploitability": exploitability,
        "impact": impact,
        "base_score": base_score
    }


# ---------------------------------------------------------
# Component context
# ---------------------------------------------------------

def calculate_component_context(
    criticality,
    data_sensitivity
):
    """
    Store component-specific contextual information.

    These values are not CVSS values.
    They represent the importance of the component
    within the IoMT architecture.
    """

    return {
        "criticality": criticality,
        "data_sensitivity": data_sensitivity
    }


# ---------------------------------------------------------
# Propagation scoring
# ---------------------------------------------------------

def calculate_propagation_score(
    reachability,
    authentication,
    authorization,
    dependency
):
    """
    Calculate a simple architecture-edge propagation score.

    This is a proposed prototype rubric.
    It is NOT a standardized CVSS calculation.

    Each factor is explicitly scored using defined
    categorical values instead of arbitrary decimal inputs.
    """

    reachability_values = {
        "None": 0.0,
        "Restricted": 0.25,
        "Direct": 1.0
    }

    authentication_values = {
        "Strong": 0.25,
        "Weak": 0.60,
        "None": 1.0
    }

    authorization_values = {
        "Strong": 0.25,
        "Weak": 0.60,
        "None": 1.0
    }

    dependency_values = {
        "Low": 0.25,
        "Medium": 0.60,
        "High": 1.0
    }

    score = (
        reachability_values[reachability]
        * authentication_values[authentication]
        * authorization_values[authorization]
        * dependency_values[dependency]
    )

    return score


# ---------------------------------------------------------
# Path propagation
# ---------------------------------------------------------

def calculate_path_propagation(edge_scores):
    """
    Calculate cumulative propagation potential
    across an attack path.
    """

    probability = 1.0

    for score in edge_scores:
        probability *= score

    return probability