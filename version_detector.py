import subprocess
import re


CONTAINERS = {
    "Mosquitto": "mosquitto-lab",
    "Mosquitto Vulnerable Lab": "mosquitto-vuln-lab",
    "InfluxDB": "influxdb-lab",
    "Eclipse Ditto": "docker-things-1"
}


def get_container_image(container_name):
    """Get the Docker image used by a container."""

    try:
        result = subprocess.run(
            [
                "docker",
                "inspect",
                container_name,
                "--format",
                "{{.Config.Image}}"
            ],
            capture_output=True,
            text=True,
            check=True
        )

        return result.stdout.strip()

    except subprocess.CalledProcessError:
        return None


def extract_version(image_name):
    """
    Extract the version/tag from a Docker image.

    Examples:
        eclipse-mosquitto:2.1.2-alpine → 2.1.2
        influxdb:2.7.11              → 2.7.11
        eclipse/ditto-things:latest  → latest
    """

    if not image_name:
        return None

    if ":" not in image_name:
        return "latest"

    tag = image_name.rsplit(":", 1)[1]

    if tag == "latest":
        return "latest"

    # Remove common suffixes such as -alpine
    match = re.match(
        r"(\d+(?:\.\d+)+)",
        tag
    )

    if match:
        return match.group(1)

    return tag


def detect_versions():
    """
    Detect versions of software running in Docker.
    """

    detected = {}

    for software, container in CONTAINERS.items():

        image = get_container_image(container)

        if image is None:
            detected[software] = {
                "container": container,
                "image": None,
                "version": None,
                "status": "Container not found"
            }

            continue

        version = extract_version(image)

        detected[software] = {
            "container": container,
            "image": image,
            "version": version,
            "status": "Detected"
        }

    return detected


if __name__ == "__main__":

    print()
    print("Automatic Software Version Detection")
    print()

    versions = detect_versions()

    for software, info in versions.items():

        print(f"{software}")

        print(
            f"  Container: "
            f"{info['container']}"
        )

        print(
            f"  Image: "
            f"{info['image']}"
        )

        print(
            f"  Version: "
            f"{info['version']}"
        )

        print(
            f"  Status: "
            f"{info['status']}"
        )

        print()