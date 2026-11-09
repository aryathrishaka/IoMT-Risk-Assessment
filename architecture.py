# IoMT Architecture
# Evidence-based representation of component relationships

architecture = {
    "IoMT Device": ["Mosquitto"],
    "Mosquitto": ["Eclipse Ditto"],
    "Eclipse Ditto": ["InfluxDB"],
    "InfluxDB": ["Healthcare Monitoring"],
    "Healthcare Monitoring": []
}

# Evidence status:
# SUPPORTED     - Evidence supports the stated relationship.
# NOT_SUPPORTED - Evidence indicates the relationship is absent
#                 under the tested configuration.
# UNKNOWN       - Insufficient evidence to decide.
#
# These statuses describe evidence, not exploit success.

relationships = {
    ("IoMT Device", "Mosquitto"): {
        "relationship_type": "data_flow",
        "status": "UNKNOWN",
        "evidence": [],
        "notes": "Evidence for device-to-broker communication is required."
    },
    ("Mosquitto", "Eclipse Ditto"): {
        "relationship_type": "data_flow",
        "status": "UNKNOWN",
        "evidence": [],
        "notes": "Evidence for broker-to-digital-twin communication is required."
    },
    ("Eclipse Ditto", "InfluxDB"): {
        "relationship_type": "data_flow",
        "status": "UNKNOWN",
        "evidence": [],
        "notes": "Evidence for digital-twin-to-database communication is required."
    },
    ("InfluxDB", "Healthcare Monitoring"): {
        "relationship_type": "data_flow",
        "status": "UNKNOWN",
        "evidence": [],
        "notes": "Evidence for database-to-monitoring communication is required."
    }
}


def get_attack_path(start_component):
    """Return the current linear downstream path from a component."""
    if start_component not in architecture:
        raise ValueError(f"Unknown component: {start_component}")

    path = []
    current = start_component

    while current:
        path.append(current)
        connections = architecture[current]

        if not connections:
            break

        # This preserves the current linear architecture.
        # Branching support can be added separately.
        current = connections[0]

    return path


def get_degree(component):
    """Return the number of outgoing connections."""
    if component not in architecture:
        raise ValueError(f"Unknown component: {component}")

    return len(architecture[component])


def get_relationship(source, destination):
    """Return evidence associated with a component relationship."""
    return relationships.get((source, destination))