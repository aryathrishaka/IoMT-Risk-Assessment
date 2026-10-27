# IoMT Architecture
# Graph representation with relationship properties


architecture = {
    "IoMT Device": ["Mosquitto"],
    "Mosquitto": ["Eclipse Ditto"],
    "Eclipse Ditto": ["InfluxDB"],
    "InfluxDB": ["Healthcare Monitoring"],
    "Healthcare Monitoring": []
}


# ---------------------------------------------------------
# Relationship properties
# ---------------------------------------------------------

relationships = {

    ("IoMT Device", "Mosquitto"): {
        "reachability": "Direct",
        "authentication": "Strong",
        "authorization": "Strong",
        "dependency": "High"
    },

    ("Mosquitto", "Eclipse Ditto"): {
        "reachability": "Direct",
        "authentication": "Weak",
        "authorization": "Weak",
        "dependency": "High"
    },

    ("Eclipse Ditto", "InfluxDB"): {
        "reachability": "Direct",
        "authentication": "Strong",
        "authorization": "Strong",
        "dependency": "High"
    },

    ("InfluxDB", "Healthcare Monitoring"): {
        "reachability": "Direct",
        "authentication": "Strong",
        "authorization": "Strong",
        "dependency": "High"
    }
}


def get_attack_path(start_component):
    """
    Find the downstream path from a selected component.
    """

    current = start_component
    path = []

    while current:

        path.append(current)

        connections = architecture[current]

        if not connections:
            break

        current = connections[0]

    return path


def get_degree(component):
    """
    Return number of direct outgoing connections.
    """

    return len(architecture[component])


def get_relationship(source, destination):
    """
    Return the relationship properties between two components.
    """

    return relationships.get(
        (source, destination)
    )