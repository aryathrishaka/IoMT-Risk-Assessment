# ---------------------------------------------------------
# Architecture Impact Analysis
# ---------------------------------------------------------
# Maps a validated vulnerability to the IoMT architecture.
#
# The downstream path is reported as a potential propagation
# path. A component is NOT marked as affected unless there
# is experimental evidence.
# ---------------------------------------------------------

from architecture import (
    get_attack_path,
    get_relationship
)


def analyze_architecture_impact(validation_result):
    """
    Map a validated vulnerability to the architecture.
    """

    component = validation_result[
        "affected_component"
    ]

    validation_status = validation_result[
        "validation_status"
    ]

    path = get_attack_path(
        component
    )

    return {
        "cve_id": validation_result["cve_id"],
        "affected_component": component,
        "validation_status": validation_status,
        "potential_path": path
    }


def print_architecture_impact(result):

    print()
    print("Architecture Impact Analysis")
    print("============================")
    print()

    print(
        f"CVE                 : "
        f"{result['cve_id']}"
    )

    print(
        f"Validated component : "
        f"{result['affected_component']}"
    )

    print(
        f"Validation status   : "
        f"{result['validation_status']}"
    )

    print()
    print("Potential downstream path:")

    path = result["potential_path"]

    for index, component in enumerate(path):

        if index == 0:
            print(
                f"  {component}"
            )
        else:
            previous = path[index - 1]

            relationship = get_relationship(
                previous,
                component
            )

            print(
                f"    ↓"
            )

            print(
                f"  {component}"
            )

            if relationship:
                print(
                    f"    Relationship: "
                    f"{relationship}"
                )

    print()
    print(
        "Note: downstream components are not "
        "considered affected without experimental evidence."
    )


# ---------------------------------------------------------
# Standalone demonstration
# ---------------------------------------------------------

if __name__ == "__main__":

    from cve_2018_12546_test import (
        validate_cve_2018_12546
    )

    validation = validate_cve_2018_12546()

    result = analyze_architecture_impact(
        validation
    )

    print_architecture_impact(
        result
    )