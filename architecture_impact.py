# Architecture Impact Analysis
# Evidence-aware assessment of potential downstream impact.

from architecture import architecture, get_relationship


VALID_STATUSES = {"SUPPORTED", "NOT_SUPPORTED", "UNKNOWN"}


def analyze_architecture_impact(validation_result):
    """
    Map a validated vulnerability to the architecture.

    A downstream connection does not, by itself, prove that
    a vulnerability can propagate to another component.
    """
    component = validation_result["affected_component"]
    validation_status = validation_result["validation_status"]

    if component not in architecture:
        raise ValueError(f"Unknown component: {component}")

    path = []
    transitions = []

    current_path = [component]
    current = component

    while architecture[current]:
        destination = architecture[current][0]
        relationship = get_relationship(current, destination)

        if relationship is None:
            relationship = {
                "relationship_type": "data_flow",
                "status": "UNKNOWN",
                "evidence": [],
                "notes": "No relationship evidence record exists."
            }

        status = relationship.get("status", "UNKNOWN")

        if status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid relationship status for "
                f"{current} -> {destination}: {status}"
            )

        transitions.append({
            "source": current,
            "destination": destination,
            "relationship_type": relationship.get(
                "relationship_type", "unknown"
            ),
            "status": status,
            "evidence": relationship.get("evidence", []),
            "notes": relationship.get("notes", "")
        })

        current_path.append(destination)
        current = destination

    path = current_path

    return {
        "cve_id": validation_result["cve_id"],
        "affected_component": component,
        "validation_status": validation_status,
        "potential_path": path,
        "transitions": transitions
    }


def print_architecture_impact(result):
    """Print the potential path and evidence status of each transition."""
    print("\nArchitecture Impact Analysis")
    print("=" * 40)
    print(f"CVE                 : {result['cve_id']}")
    print(f"Affected component  : {result['affected_component']}")
    print(f"Validation status   : {result['validation_status']}")

    print("\nPotential downstream path:")
    print(" -> ".join(result["potential_path"]))

    print("\nRelationship evidence:")
    for transition in result["transitions"]:
        print(
            f"\n{transition['source']} -> "
            f"{transition['destination']}"
        )
        print(f"  Status : {transition['status']}")
        print(f"  Type   : {transition['relationship_type']}")
        print(f"  Notes  : {transition['notes']}")

        evidence = transition["evidence"]
        if evidence:
            for item in evidence:
                print(f"  Evidence: {item}")
        else:
            print("  Evidence: None recorded")

    print("\nInterpretation:")
    print(
        "The path represents potential downstream connectivity. "
        "UNKNOWN means insufficient evidence; it does not mean "
        "the transition is impossible. No downstream component "
        "is automatically classified as affected."
    )


if __name__ == "__main__":
    from cve_2018_12546_test import validate_cve_2018_12546

    validation = validate_cve_2018_12546()
    result = analyze_architecture_impact(validation)
    print_architecture_impact(result)