# CVSS Model
# Handles CVSS v3.0 and v3.1 vectors retrieved from NVD.
#
# CVSS is used here to represent vulnerability severity.
# It is NOT the complete architecture/system risk score.

import math


# ---------------------------------------------------------
# CVSS v3.x metric values
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

UI_VALUES = {
    "N": 0.85,   # None
    "R": 0.62    # Required
}

CIA_VALUES = {
    "N": 0.00,   # None
    "L": 0.22,   # Low
    "H": 0.56    # High
}


def roundup(value):
    """
    CVSS Roundup function.

    Rounds upward to one decimal place.
    """
    return math.ceil(value * 10) / 10


def parse_cvss_vector(vector):
    """
    Convert a CVSS v3.x vector string into a dictionary.

    Example:
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    """

    if not vector:
        raise ValueError("CVSS vector is missing.")

    parts = vector.split("/")

    metrics = {}

    for part in parts[1:]:
        if ":" not in part:
            continue

        key, value = part.split(":", 1)
        metrics[key] = value

    return metrics


def get_pr_value(pr, scope):
    """
    Privileges Required has different values depending
    on whether Scope is Unchanged or Changed.
    """

    if scope == "U":
        values = {
            "N": 0.85,
            "L": 0.62,
            "H": 0.27
        }

    else:
        values = {
            "N": 0.85,
            "L": 0.68,
            "H": 0.50
        }

    return values[pr]


def calculate_exploitability(metrics):
    """
    Calculate the standardized CVSS v3.x
    Exploitability sub-score.

    Exploitability =
    8.22 × AV × AC × PR × UI
    """

    av = AV_VALUES[metrics["AV"]]
    ac = AC_VALUES[metrics["AC"]]

    scope = metrics["S"]

    pr = get_pr_value(
        metrics["PR"],
        scope
    )

    ui = UI_VALUES[metrics["UI"]]

    exploitability = (
        8.22
        * av
        * ac
        * pr
        * ui
    )

    return exploitability


def calculate_impact(metrics):
    """
    Calculate the CVSS v3.x Impact sub-score.
    """

    c = CIA_VALUES[metrics["C"]]
    i = CIA_VALUES[metrics["I"]]
    a = CIA_VALUES[metrics["A"]]

    isc_base = 1 - (
        (1 - c)
        * (1 - i)
        * (1 - a)
    )

    if metrics["S"] == "U":

        impact = 6.42 * isc_base

    else:

        impact = (
            7.52 * (isc_base - 0.029)
            - 3.25 * (isc_base - 0.02) ** 15
        )

    return impact


def calculate_base_score(metrics):
    """
    Calculate the CVSS v3.x Base Score.
    """

    impact = calculate_impact(metrics)
    exploitability = calculate_exploitability(metrics)

    if impact <= 0:
        return 0.0

    total = impact + exploitability

    if metrics["S"] == "U":

        base_score = roundup(
            min(total, 10)
        )

    else:

        base_score = roundup(
            min(1.08 * total, 10)
        )

    return base_score


def calculate_cvss(vector):
    """
    Calculate CVSS components from a CVSS v3.x vector.

    Returns:
        Dictionary containing:
        - metrics
        - exploitability
        - impact
        - base_score
    """

    metrics = parse_cvss_vector(vector)

    required = [
        "AV",
        "AC",
        "PR",
        "UI",
        "S",
        "C",
        "I",
        "A"
    ]

    missing = [
        metric
        for metric in required
        if metric not in metrics
    ]

    if missing:
        raise ValueError(
            f"Missing CVSS metrics: {missing}"
        )

    exploitability = calculate_exploitability(
        metrics
    )

    impact = calculate_impact(
        metrics
    )

    base_score = calculate_base_score(
        metrics
    )

    return {
        "metrics": metrics,
        "exploitability": exploitability,
        "impact": impact,
        "base_score": base_score
    }


# ---------------------------------------------------------
# Test
# ---------------------------------------------------------

if __name__ == "__main__":

    test_vector = (
        "CVSS:3.0/"
        "AV:N/"
        "AC:H/"
        "PR:N/"
        "UI:N/"
        "S:U/"
        "C:H/"
        "I:H/"
        "A:H"
    )

    result = calculate_cvss(
        test_vector
    )

    print()
    print("CVSS Model Test")
    print("================")

    print(
        f"Vector: {test_vector}"
    )

    print(
        f"Exploitability: "
        f"{result['exploitability']:.3f}"
    )

    print(
        f"Impact: "
        f"{result['impact']:.3f}"
    )

    print(
        f"Base Score: "
        f"{result['base_score']:.1f}"
    )