"""Registry-driven discovery of IoMT software running in Docker."""

import json
import re
import subprocess


DOCKER_TIMEOUT_SECONDS = 10

DISCOVERY_COMPLETE = "COMPLETE"
DISCOVERY_PARTIAL = "PARTIAL"
DOCKER_UNAVAILABLE = "DOCKER_UNAVAILABLE"
DOCKER_TIMEOUT = "DOCKER_TIMEOUT"
DOCKER_ERROR = "DOCKER_ERROR"
MALFORMED_OUTPUT = "MALFORMED_OUTPUT"

INSTANCE_DETECTED = "DETECTED"
INSTANCE_VERSION_UNKNOWN = "VERSION_UNKNOWN"
INSTANCE_VERSION_CONFLICT = "VERSION_CONFLICT"
INSTANCE_AMBIGUOUS = "AMBIGUOUS"
INSTANCE_PARTIAL = "PARTIAL"


COMPONENT_REGISTRY = {
    "mosquitto": {
        "display_name": "Mosquitto",
        "nvd_search_term": "mosquitto",
        "cpe_vendor": "eclipse",
        "cpe_product": "mosquitto",
        "image_repositories": {"eclipse-mosquitto"},
        "compose_services": {"mosquitto"},
        "runtime_probe": {
            "executable": "mosquitto",
            "arguments": ["-h"],
            "product_pattern": r"mosquitto\s+version\s+",
            "version_pattern": (
                r"mosquitto\s+version\s+"
                r"v?([0-9]+(?:\.[0-9]+)+[a-zA-Z0-9._-]*)"
            )
        },
        "multi_service": False
    },
    "influxdb": {
        "display_name": "InfluxDB",
        "nvd_search_term": "influxdb",
        "cpe_vendor": "influxdata",
        "cpe_product": "influxdb",
        "image_repositories": {"influxdb"},
        "compose_services": {"influxdb"},
        "runtime_probe": None,
        "multi_service": False
    },
    "ditto": {
        "display_name": "Eclipse Ditto",
        "nvd_search_term": "ditto",
        "cpe_vendor": "eclipse",
        "cpe_product": "ditto",
        "image_repository_prefixes": {"eclipse/ditto-"},
        "compose_services": {
            "gateway",
            "things",
            "policies",
            "connectivity",
            "concierge",
            "search"
        },
        "runtime_probe": None,
        "multi_service": True
    }
}

_COMPONENT_ALIASES = {
    "mosquitto": "mosquitto",
    "eclipse mosquitto": "mosquitto",
    "influxdb": "influxdb",
    "influx db": "influxdb",
    "ditto": "ditto",
    "eclipse ditto": "ditto"
}

_REGISTRY_PREFIXES = {
    "docker.io",
    "index.docker.io",
    "registry-1.docker.io"
}

_VERSION_PATTERN = re.compile(
    r"^v?(\d+(?:\.\d+)+)(?:[-_].*)?$",
    re.IGNORECASE
)


def parse_image_reference(image_reference):
    """Parse a Docker image reference without resolving an IP address."""

    if not isinstance(image_reference, str) or not image_reference.strip():
        return {
            "original": image_reference,
            "repository": None,
            "tag": None,
            "digest": None
        }

    original = image_reference.strip()
    reference_without_digest, separator, digest = original.partition("@")

    if not separator:
        digest = None

    last_slash = reference_without_digest.rfind("/")
    last_colon = reference_without_digest.rfind(":")

    if last_colon > last_slash:
        repository = reference_without_digest[:last_colon]
        tag = reference_without_digest[last_colon + 1:]
    else:
        repository = reference_without_digest
        tag = None

    repository_parts = repository.split("/")

    if repository_parts and repository_parts[0] in _REGISTRY_PREFIXES:
        repository_parts = repository_parts[1:]

    if repository_parts and repository_parts[0] == "library":
        repository_parts = repository_parts[1:]

    repository = "/".join(repository_parts).lower()

    return {
        "original": original,
        "repository": repository or None,
        "tag": tag,
        "digest": digest
    }


def _version_from_text(value):
    """Extract one version candidate from a tag or OCI version label."""

    if not isinstance(value, str):
        return None

    value = value.strip()

    if not value or value.lower() == "latest":
        return None

    match = _VERSION_PATTERN.fullmatch(value)

    if not match:
        return None

    return match.group(1)


def extract_version(image_name):
    """Return a version candidate from an image tag, or None if unknown."""

    parsed = parse_image_reference(image_name)
    return _version_from_text(parsed["tag"])


def _component_from_image_repository(repository):
    """Return the canonical component indicated by a known image repository."""

    if not repository:
        return None

    for component_id, definition in COMPONENT_REGISTRY.items():

        if repository in definition.get("image_repositories", set()):
            return component_id

        if any(
            repository.startswith(prefix)
            for prefix in definition.get(
                "image_repository_prefixes",
                set()
            )
        ):
            return component_id

    return None


def _component_from_label(value):
    if not isinstance(value, str):
        return None

    return _COMPONENT_ALIASES.get(value.strip().lower())


def _component_from_service(service):
    if not isinstance(service, str):
        return None

    service = service.strip().lower()

    for component_id, definition in COMPONENT_REGISTRY.items():

        if service in definition.get("compose_services", set()):
            return component_id

    return None


def _docker_result(status, stdout=None, stderr=None, error=None):
    return {
        "status": status,
        "stdout": stdout,
        "stderr": stderr,
        "error": error
    }


def _run_docker(arguments):
    """Run one read-only Docker command and return a status-aware result."""

    try:

        completed = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            timeout=DOCKER_TIMEOUT_SECONDS,
            check=False
        )

    except FileNotFoundError:

        return _docker_result(
            DOCKER_UNAVAILABLE,
            error="Docker executable was not found."
        )

    except subprocess.TimeoutExpired:

        return _docker_result(
            DOCKER_TIMEOUT,
            error="Docker command timed out."
        )

    except OSError as error:

        return _docker_result(
            DOCKER_ERROR,
            error=f"Docker command failed: {error}"
        )

    if completed.returncode != 0:

        detail = (completed.stderr or completed.stdout or "").strip()
        return _docker_result(
            DOCKER_ERROR,
            stdout=completed.stdout,
            stderr=completed.stderr,
            error=detail or "Docker command returned a non-zero exit code."
        )

    return _docker_result(
        DISCOVERY_COMPLETE,
        stdout=completed.stdout,
        stderr=completed.stderr
    )


def _image_metadata(image_objects):
    """Index image-inspect results by local image ID."""

    metadata = {}

    for image in image_objects:

        if not isinstance(image, dict):
            continue

        image_id = image.get("Id")

        if image_id:
            metadata[image_id] = image

    return metadata


def _select_digest(reference, repository, image_info):
    if reference.get("digest"):
        return reference["digest"]

    repo_digests = image_info.get("RepoDigests") or []

    if not isinstance(repo_digests, list):
        repo_digests = []

    for repo_digest in repo_digests:

        parsed = parse_image_reference(repo_digest)

        if parsed["repository"] == repository and parsed["digest"]:
            return parsed["digest"]

    if repo_digests:
        parsed = parse_image_reference(repo_digests[0])
        return parsed["digest"]

    return None


def _version_evidence(
    tag,
    container_labels,
    image_labels,
    runtime_probe=None
):
    tag_version = _version_from_text(tag)
    container_label_version = _version_from_text(
        (container_labels or {}).get("io.iomt.version")
    )
    image_label_version = _version_from_text(
        (image_labels or {}).get("io.iomt.version")
    )
    runtime_version = (
        runtime_probe.get("version")
        if runtime_probe
        else None
    )
    application_versions = {
        version
        for version in (
            tag_version,
            container_label_version,
            image_label_version,
            runtime_version
        )
        if version
    }

    if len(application_versions) > 1:
        return (
            None,
            "conflicting_application_version_evidence",
            INSTANCE_VERSION_CONFLICT,
            {
                "image_tag": tag_version,
                "container_io_iomt_version": container_label_version,
                "image_io_iomt_version": image_label_version,
                "runtime": runtime_version
            }
        )

    evidence_sources = {
        "image_tag": tag_version,
        "container_io_iomt_version": container_label_version,
        "image_io_iomt_version": image_label_version,
        "runtime": runtime_version
    }

    if runtime_version:
        return (
            runtime_version,
            "runtime_probe",
            INSTANCE_DETECTED,
            evidence_sources
        )

    if tag_version:
        return (
            tag_version,
            "image_tag",
            INSTANCE_DETECTED,
            evidence_sources
        )

    if container_label_version:
        return (
            container_label_version,
            "io.iomt.version",
            INSTANCE_DETECTED,
            evidence_sources
        )

    if image_label_version:
        return (
            image_label_version,
            "image_io.iomt.version",
            INSTANCE_DETECTED,
            evidence_sources
        )

    return (
        None,
        None,
        INSTANCE_VERSION_UNKNOWN,
        evidence_sources
    )


def _deployment_metadata(labels, container_name):
    project = labels.get("com.docker.compose.project")
    service = labels.get("com.docker.compose.service")
    deployment_label = (
        labels.get("io.iomt.deployment")
        or labels.get("io.iomt.deployment_name")
    )

    if deployment_label:
        deployment_id = deployment_label
    elif project and service:
        deployment_id = f"{project}/{service}"
    elif container_name:
        deployment_id = container_name
    else:
        deployment_id = None

    return project, service, deployment_id


def _runtime_probe_candidate(container, image_info):
    """Return whether a container should receive the Mosquitto probe."""

    config = container.get("Config")

    if not isinstance(config, dict):
        config = {}

    labels = config.get("Labels") or {}

    if not isinstance(labels, dict):
        labels = {}

    image_reference = config.get("Image")
    reference = parse_image_reference(image_reference)
    label_component = _component_from_label(
        labels.get("io.iomt.component")
    )
    image_component = _component_from_image_repository(
        reference["repository"]
    )
    service_component = _component_from_service(
        labels.get("com.docker.compose.service")
    )

    if "mosquitto" in (
        label_component,
        image_component,
        service_component
    ):
        return True

    repository_leaf = (
        reference["repository"].rsplit("/", 1)[-1]
        if reference["repository"]
        else ""
    )

    # Repository text is only a probe hint. Runtime output must establish
    # product identity for unrecognised repositories.
    return "mosquitto" in repository_leaf


def _probe_mosquitto(container_id, run_docker):
    """Probe Mosquitto using the container ID, never its display name."""

    if not container_id:
        return {
            "status": "SKIPPED",
            "product_evidence": False,
            "version": None,
            "command": None,
            "output": None
        }

    command = [
        "docker",
        "exec",
        container_id,
        "mosquitto",
        "-h"
    ]
    result = run_docker(command)
    output = "\n".join(
        part
        for part in (
            result.get("stdout"),
            result.get("stderr"),
            result.get("error")
        )
        if part
    ).strip()
    probe_definition = COMPONENT_REGISTRY["mosquitto"][
        "runtime_probe"
    ]
    product_match = re.search(
        probe_definition["product_pattern"],
        output,
        re.IGNORECASE
    )
    version_match = re.search(
        probe_definition["version_pattern"],
        output,
        re.IGNORECASE
    )

    if version_match:
        return {
            "status": "DETECTED",
            "product_evidence": True,
            "version": version_match.group(1),
            "command": command,
            "output": output
        }

    if product_match:
        return {
            "status": "PRODUCT_ONLY",
            "product_evidence": True,
            "version": None,
            "command": command,
            "output": output
        }

    return {
        "status": (
            "COMMAND_FAILED"
            if result.get("status") != DISCOVERY_COMPLETE
            else "UNRECOGNISED_OUTPUT"
        ),
        "product_evidence": False,
        "version": None,
        "command": command,
        "output": output or None
    }


def _classify_container(container, image_info, runtime_probe=None):
    config = container.get("Config")

    if not isinstance(config, dict):
        config = {}

    labels = config.get("Labels") or {}

    if not isinstance(labels, dict):
        labels = {}

    image_config = image_info.get("Config") if image_info else {}

    if not isinstance(image_config, dict):
        image_config = {}

    image_labels = image_config.get("Labels") or {}

    if not isinstance(image_labels, dict):
        image_labels = {}

    image_reference = config.get("Image")
    reference = parse_image_reference(image_reference)
    container_name = container.get("Name")

    if not isinstance(container_name, str):
        container_name = ""

    container_name = container_name.lstrip("/")
    project, service, deployment_id = _deployment_metadata(
        labels,
        container_name
    )

    label_component = _component_from_label(
        labels.get("io.iomt.component")
    )
    image_component = _component_from_image_repository(
        reference["repository"]
    )
    service_component = _component_from_service(service)

    component_id = None
    classification_source = []
    status = INSTANCE_DETECTED
    reason = None
    identity_conflict = False

    if label_component:
        classification_source.append("component_label")
        component_id = label_component

    if image_component:
        classification_source.append("image_repository")

        if component_id and component_id != image_component:
            component_id = None
            status = INSTANCE_AMBIGUOUS
            reason = "Component label and image repository disagree."
            identity_conflict = True
        elif component_id is None:
            component_id = image_component

    if service_component:
        classification_source.append("compose_service")

        if component_id and component_id != service_component:
            component_id = None
            status = INSTANCE_AMBIGUOUS
            reason = "Compose service and component evidence disagree."
            identity_conflict = True

    runtime_establishes_product = bool(
        runtime_probe
        and runtime_probe.get("product_evidence")
    )

    if (
        component_id is None
        and runtime_establishes_product
        and not identity_conflict
    ):
        component_id = "mosquitto"
        classification_source.append("runtime_probe_product")
        status = INSTANCE_DETECTED
        reason = None

    if component_id is None and status != INSTANCE_AMBIGUOUS:

        if service_component:
            status = INSTANCE_AMBIGUOUS
            reason = (
                "Compose service suggests a product, but the image "
                "repository is not recognised."
            )
        else:
            status = INSTANCE_VERSION_UNKNOWN
            reason = "No supported product evidence was found."

    (
        version,
        version_source,
        version_status,
        version_evidence
    ) = _version_evidence(
        reference["tag"],
        labels,
        image_labels,
        runtime_probe
    )

    if status == INSTANCE_DETECTED and version_status != INSTANCE_DETECTED:
        status = version_status

    cpe_ready = (
        component_id is not None
        and version is not None
        and status == INSTANCE_DETECTED
    )

    return {
        "instance_id": container.get("Id"),
        "container_names": [container_name] if container_name else [],
        "compose_project": project,
        "compose_service": service,
        "deployment_id": deployment_id,
        "component_id": component_id,
        "display_name": (
            labels.get("io.iomt.display_name")
            or (
                COMPONENT_REGISTRY[component_id]["display_name"]
                if component_id
                else None
            )
        ),
        "cpe_vendor": (
            COMPONENT_REGISTRY[component_id]["cpe_vendor"]
            if component_id and cpe_ready
            else None
        ),
        "cpe_product": (
            COMPONENT_REGISTRY[component_id]["cpe_product"]
            if component_id and cpe_ready
            else None
        ),
        "image_reference": image_reference,
        "image_repository": reference["repository"],
        "image_tag": reference["tag"],
        "image_digest": _select_digest(
            reference,
            reference["repository"],
            image_info
        ),
        "image_id": (
            container.get("Image")
            or (image_info or {}).get("Id")
        ),
        "version": version,
        "version_source": version_source,
        "oci_version_label": image_labels.get(
            "org.opencontainers.image.version"
        ),
        "application_version_label": (
            labels.get("io.iomt.version")
            or image_labels.get("io.iomt.version")
        ),
        "application_version_evidence": version_evidence,
        "runtime_probe": runtime_probe,
        "cpe_identity_usable": cpe_ready,
        "status": status,
        "classification_source": classification_source,
        "reason": reason
    }


def _component_summaries(instances):
    """Summarise canonical components by deployment group."""

    summaries = []

    for component_id, definition in COMPONENT_REGISTRY.items():

        component_instances = [
            instance
            for instance in instances
            if instance["component_id"] == component_id
        ]

        if not component_instances:
            continue

        deployment_groups = {}

        for instance in component_instances:

            if definition["multi_service"]:
                group_id = (
                    instance.get("compose_project")
                    or instance.get("deployment_id")
                    or instance.get("instance_id")
                )
            else:
                group_id = (
                    instance.get("deployment_id")
                    or instance.get("instance_id")
                )

            deployment_groups.setdefault(group_id, []).append(
                instance
            )

        for deployment_id, group_instances in deployment_groups.items():

            versions = sorted({
                instance["version"]
                for instance in group_instances
                if instance["version"]
            })
            statuses = {
                instance["status"]
                for instance in group_instances
            }

            if INSTANCE_AMBIGUOUS in statuses:
                status = INSTANCE_AMBIGUOUS
            elif INSTANCE_VERSION_CONFLICT in statuses:
                status = INSTANCE_VERSION_CONFLICT
            elif len(versions) > 1:
                status = "MIXED"
            elif not versions:
                status = INSTANCE_VERSION_UNKNOWN
            elif any(
                state != INSTANCE_DETECTED
                for state in statuses
            ):
                status = INSTANCE_PARTIAL
            else:
                status = INSTANCE_DETECTED

            summaries.append({
                "component_id": component_id,
                "deployment_id": deployment_id,
                "display_name": definition["display_name"],
                "cpe_vendor": definition["cpe_vendor"],
                "cpe_product": definition["cpe_product"],
                "status": status,
                "version": versions[0] if len(versions) == 1 else None,
                "versions": versions,
                "instance_ids": [
                    instance["instance_id"]
                    for instance in group_instances
                ],
                "multi_service": definition["multi_service"]
            })

    return summaries


def discover_software_instances(run_docker=None):
    """
    Discover running software deployments without classifying by container
    name.

    Returns status, instances, canonical component summaries and unclassified
    container evidence.
    """

    docker = run_docker or _run_docker
    container_ids_result = docker([
        "docker",
        "ps",
        "--quiet",
        "--no-trunc"
    ])

    if container_ids_result["status"] != DISCOVERY_COMPLETE:
        return {
            "status": container_ids_result["status"],
            "error": container_ids_result["error"],
            "instances": [],
            "components": [],
            "unclassified": []
        }

    container_ids = [
        line.strip()
        for line in (container_ids_result["stdout"] or "").splitlines()
        if line.strip()
    ]

    if not container_ids:
        return {
            "status": DISCOVERY_COMPLETE,
            "error": None,
            "instances": [],
            "components": [],
            "unclassified": []
        }

    inspect_result = docker([
        "docker",
        "inspect",
        *container_ids
    ])

    if inspect_result["status"] != DISCOVERY_COMPLETE:
        return {
            "status": inspect_result["status"],
            "error": inspect_result["error"],
            "instances": [],
            "components": [],
            "unclassified": []
        }

    try:
        containers = json.loads(inspect_result["stdout"] or "[]")
    except (json.JSONDecodeError, TypeError) as error:
        return {
            "status": MALFORMED_OUTPUT,
            "error": f"Malformed container inspect JSON: {error}",
            "instances": [],
            "components": [],
            "unclassified": []
        }

    if not isinstance(containers, list):
        return {
            "status": MALFORMED_OUTPUT,
            "error": "Container inspect output was not a JSON array.",
            "instances": [],
            "components": [],
            "unclassified": []
        }

    image_ids = sorted({
        container.get("Image")
        for container in containers
        if isinstance(container, dict) and container.get("Image")
    })
    image_metadata = {}
    discovery_status = DISCOVERY_COMPLETE
    discovery_error = None

    if image_ids:

        image_result = docker([
            "docker",
            "image",
            "inspect",
            *image_ids
        ])

        if image_result["status"] == DISCOVERY_COMPLETE:

            try:
                image_objects = json.loads(
                    image_result["stdout"] or "[]"
                )

                if not isinstance(image_objects, list):
                    raise ValueError(
                        "image inspect output is not a JSON array"
                    )

                image_metadata = _image_metadata(image_objects)

            except (json.JSONDecodeError, TypeError, ValueError) as error:

                discovery_status = DISCOVERY_PARTIAL
                discovery_error = f"Malformed image inspect JSON: {error}"

        else:

            discovery_status = DISCOVERY_PARTIAL
            discovery_error = image_result["error"]

    instances = []
    unclassified = []

    for container in containers:

        if not isinstance(container, dict):
            unclassified.append({
                "reason": "Container inspect entry is not an object.",
                "entry": container
            })
            continue

        image_info = image_metadata.get(container.get("Image"), {})
        runtime_probe = None

        if _runtime_probe_candidate(container, image_info):
            runtime_probe = _probe_mosquitto(
                container.get("Id"),
                docker
            )

        instance = _classify_container(
            container,
            image_info,
            runtime_probe
        )

        if discovery_status == DISCOVERY_PARTIAL:

            if instance["status"] == INSTANCE_DETECTED:
                instance["status"] = INSTANCE_PARTIAL

            if not instance["reason"]:
                instance["reason"] = discovery_error

        instances.append(instance)

        if instance["component_id"] is None:
            unclassified.append(instance)

    components = _component_summaries(instances)

    if (
        discovery_status == DISCOVERY_COMPLETE
        and (
            unclassified
            or any(
                component["status"] != INSTANCE_DETECTED
                for component in components
            )
        )
    ):
        discovery_status = DISCOVERY_PARTIAL

    return {
        "status": discovery_status,
        "error": discovery_error,
        "instances": instances,
        "components": components,
        "unclassified": unclassified
    }


def _compatibility_display_name(instance, instances):
    component_instances = [
        item
        for item in instances
        if item["component_id"] == instance["component_id"]
    ]
    explicit = instance.get("display_name")

    if len(component_instances) == 1:
        return explicit or instance["component_id"]

    deployment = (
        instance.get("deployment_id")
        or instance.get("container_names", [None])[0]
        or instance.get("instance_id")
    )

    return f"{explicit or instance['component_id']} [{deployment}]"


def _ditto_compatibility_record(summary, instances):
    instance_ids = set(summary.get("instance_ids", []))
    ditto_instances = [
        instance
        for instance in instances
        if (
            instance["component_id"] == "ditto"
            and instance["instance_id"] in instance_ids
        )
    ]

    return {
        "component_id": "ditto",
        "display_name": summary["display_name"],
        "architecture_component": summary["display_name"],
        "deployment_id": summary.get("deployment_id"),
        "container": ", ".join(
            name
            for instance in ditto_instances
            for name in instance.get("container_names", [])
        ),
        "image": ", ".join(
            sorted({
                instance["image_reference"]
                for instance in ditto_instances
                if instance.get("image_reference")
            })
        ),
        "version": summary["version"],
        "status": _legacy_success_status(summary["status"]),
        "services": [
            {
                "service": instance.get("compose_service"),
                "instance_id": instance.get("instance_id"),
                "container_names": instance.get(
                    "container_names",
                    []
                ),
                "image": instance.get("image_reference"),
                "image_id": instance.get("image_id"),
                "image_repository": instance.get(
                    "image_repository"
                ),
                "image_tag": instance.get("image_tag"),
                "image_digest": instance.get("image_digest"),
                "version": instance.get("version"),
                "version_source": instance.get("version_source"),
                "application_version_evidence": instance.get(
                    "application_version_evidence"
                ),
                "runtime_probe": instance.get("runtime_probe"),
                "classification_source": instance.get(
                    "classification_source",
                    []
                ),
                "status": instance.get("status"),
                "reason": instance.get("reason"),
                "oci_version_label": instance.get(
                    "oci_version_label"
                )
            }
            for instance in ditto_instances
        ],
        "cpe": {
            "vendor": "eclipse",
            "product": "ditto"
        },
        "nvd_search_term": "ditto",
        "classification_source": sorted({
            source
            for instance in ditto_instances
            for source in instance.get(
                "classification_source",
                []
            )
        }),
        "reason": None,
        "diagnostic": False
    }


def _legacy_success_status(status):
    """Preserve the historical main.py success value."""

    if status == INSTANCE_DETECTED:
        return "Detected"

    return status


def detect_versions(run_docker=None):
    """
    Compatibility adapter for main.py and baseline.py.

    The legacy container/image/version/status fields remain available, while
    canonical component, deployment, CPE and image evidence are retained.
    """

    discovery = discover_software_instances(run_docker=run_docker)
    instances = discovery["instances"]
    detected = {}

    if discovery["status"] in (
        DOCKER_UNAVAILABLE,
        DOCKER_TIMEOUT,
        DOCKER_ERROR,
        MALFORMED_OUTPUT
    ):

        for definition in COMPONENT_REGISTRY.values():
            detected[definition["display_name"]] = {
                "component_id": None,
                "deployment_id": None,
                "container": None,
                "image": None,
                "version": None,
                "status": discovery["status"],
                "error": discovery["error"],
                "cpe": None,
                "nvd_search_term": definition["nvd_search_term"],
                "diagnostic": True
            }

        return detected

    component_summary_counts = {}

    for summary in discovery["components"]:
        component_summary_counts[summary["component_id"]] = (
            component_summary_counts.get(
                summary["component_id"],
                0
            )
            + 1
        )

    for summary in discovery["components"]:

        component_id = summary["component_id"]
        definition = COMPONENT_REGISTRY[component_id]

        if definition["multi_service"]:

            key = definition["display_name"]

            if component_summary_counts[component_id] > 1:
                key = (
                    f"{definition['display_name']} "
                    f"[{summary.get('deployment_id')}]"
                )

            detected[key] = _ditto_compatibility_record(
                summary,
                instances
            )
            continue

        component_instances = [
            instance
            for instance in instances
            if instance["component_id"] == component_id
        ]

        for instance in component_instances:

            key = _compatibility_display_name(instance, instances)
            detected[key] = {
                "component_id": component_id,
                "display_name": (
                    instance.get("display_name")
                    or definition["display_name"]
                ),
                "architecture_component": definition["display_name"],
                "deployment_id": instance.get("deployment_id"),
                "container": (
                    instance["container_names"][0]
                    if instance["container_names"]
                    else None
                ),
                "image": instance.get("image_reference"),
                "version": instance.get("version"),
                "status": _legacy_success_status(
                    instance.get("status")
                ),
                "image_id": instance.get("image_id"),
                "image_tag": instance.get("image_tag"),
                "image_digest": instance.get("image_digest"),
                "image_repository": instance.get("image_repository"),
                "version_source": instance.get("version_source"),
                "oci_version_label": instance.get(
                    "oci_version_label"
                ),
                "application_version_label": instance.get(
                    "application_version_label"
                ),
                "application_version_evidence": instance.get(
                    "application_version_evidence"
                ),
                "runtime_probe": instance.get("runtime_probe"),
                "classification_source": instance.get(
                    "classification_source",
                    []
                ),
                "reason": instance.get("reason"),
                "cpe": {
                    "vendor": instance.get("cpe_vendor"),
                    "product": instance.get("cpe_product")
                },
                "nvd_search_term": definition["nvd_search_term"],
                "diagnostic": False
            }

    for instance in discovery["unclassified"]:

        if not isinstance(instance, dict) or "instance_id" not in instance:
            deployment_name = "unknown"
            record = {
                "component_id": None,
                "deployment_id": None,
                "container": None,
                "image": None,
                "version": None,
                "status": "UNCLASSIFIED",
                "reason": instance.get("reason")
                if isinstance(instance, dict)
                else "Malformed container entry",
                "cpe": None,
                "nvd_search_term": None,
                "diagnostic": True
            }
        else:
            deployment_name = (
                instance.get("deployment_id")
                or instance.get("instance_id")
            )
            record = {
                "component_id": None,
                "deployment_id": instance.get("deployment_id"),
                "container": (
                    instance["container_names"][0]
                    if instance.get("container_names")
                    else None
                ),
                "image": instance.get("image_reference"),
                "version": instance.get("version"),
                "status": "UNCLASSIFIED",
                "reason": instance.get("reason"),
                "image_id": instance.get("image_id"),
                "image_tag": instance.get("image_tag"),
                "image_digest": instance.get("image_digest"),
                "image_repository": instance.get("image_repository"),
                "version_source": instance.get("version_source"),
                "oci_version_label": instance.get(
                    "oci_version_label"
                ),
                "application_version_evidence": instance.get(
                    "application_version_evidence"
                ),
                "runtime_probe": instance.get("runtime_probe"),
                "cpe": None,
                "nvd_search_term": None,
                "diagnostic": True
            }

        key = f"Unclassified deployment [{deployment_name}]"
        detected[key] = record

    for component_id, definition in COMPONENT_REGISTRY.items():

        present = any(
            record.get("component_id") == component_id
            for record in detected.values()
        )

        if not present:
            detected[definition["display_name"]] = {
                "component_id": None,
                "deployment_id": None,
                "container": None,
                "image": None,
                "version": None,
                "status": "Not detected",
                "error": None,
                "cpe": None,
                "nvd_search_term": definition["nvd_search_term"],
                "diagnostic": True
            }

    return detected


def get_container_image(container_name):
    """Compatibility helper for a direct container image lookup."""

    result = _run_docker([
        "docker",
        "inspect",
        container_name,
        "--format",
        "{{.Config.Image}}"
    ])

    if result["status"] != DISCOVERY_COMPLETE:
        return None

    return (result["stdout"] or "").strip() or None


if __name__ == "__main__":

    print()
    print("Automatic Software Version Detection")
    print()

    versions = detect_versions()

    for software, info in versions.items():

        print(f"{software}")
        print(f"  Container: {info['container']}")
        print(f"  Image: {info['image']}")
        print(f"  Version: {info['version']}")
        print(f"  Status: {info['status']}")
        print()
