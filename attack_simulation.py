# ---------------------------------------------------------
# Controlled Validation Framework
# ---------------------------------------------------------
# Generic framework for recording and evaluating
# vulnerability validation experiments.
#
# The actual validation procedure is supplied separately
# for each CVE.
# ---------------------------------------------------------


VALIDATION_STATUSES = {
    "VALIDATED",
    "NOT_REPRODUCED",
    "INCONCLUSIVE"
}


def run_controlled_validation(
    cve_id,
    target,
    affected_component,
    prerequisites,
    validation_procedure,
    validation_status,
    evidence=None,
    impact=None
):
    """
    Generic controlled-validation framework.

    The validation procedure is supplied by the
    CVE-specific test logic.

    No automatic exploit is executed here.
    """

    if evidence is None:
        evidence = []

    if impact is None:
        impact = []

    if validation_status not in VALIDATION_STATUSES:
        raise ValueError(
            f"Invalid validation status: "
            f"{validation_status}"
        )

    result = {
    "cve_id": cve_id,
    "target": target,
    "affected_component": affected_component,
    "prerequisites": prerequisites,
    "validation_procedure": validation_procedure,
    "validation_status": validation_status,
    "evidence": evidence,
    "impact": impact
    }

    return result


def print_validation_result(result):
    """Display a structured validation result."""

    print()
    print("Controlled CVE Validation")
    print("=========================")
    print()

    print(
        f"CVE              : "
        f"{result['cve_id']}"
    )

    print(
        f"Target           : "
        f"{result['target']}"
    )

    print()
    print("Prerequisites:")

    for item in result["prerequisites"]:
        print(f"  - {item}")

    print()
    print("Validation procedure:")
    print(
        f"  {result['validation_procedure']}"
    )

    print()
    print(
        f"Validation status: "
        f"{result['validation_status']}"
    )

    if result["evidence"]:

        print()
        print("Evidence:")

        for item in result["evidence"]:
            print(f"  - {item}")

    if result["impact"]:

        print()
        print("Observed impact:")

        for item in result["impact"]:
            print(f"  - {item}")

    print()