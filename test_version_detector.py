"""Offline tests for registry-driven Docker software discovery."""

import json
import subprocess
import unittest
from unittest.mock import patch

import version_detector


def container(
    container_id,
    name,
    image_reference,
    image_id,
    labels=None
):
    return {
        "Id": container_id,
        "Name": f"/{name}",
        "Image": image_id,
        "Config": {
            "Image": image_reference,
            "Labels": labels or {}
        }
    }


def image(image_id, repo_digest=None, labels=None):
    return {
        "Id": image_id,
        "RepoDigests": [repo_digest] if repo_digest else [],
        "Config": {
            "Labels": labels or {}
        }
    }


class FakeDockerRunner:

    def __init__(
        self,
        containers,
        images,
        ps_status=None,
        inspect_status=None,
        image_status=None,
        runtime_results=None
    ):
        self.containers = containers
        self.images = images
        self.ps_status = ps_status
        self.inspect_status = inspect_status
        self.image_status = image_status
        self.runtime_results = runtime_results or {}
        self.calls = []

    def __call__(self, arguments):
        self.calls.append(arguments)

        if arguments[1:3] == ["ps", "--quiet"]:

            if self.ps_status:
                return self.ps_status

            return {
                "status": version_detector.DISCOVERY_COMPLETE,
                "stdout": "\n".join(
                    item["Id"] for item in self.containers
                ),
                "error": None
            }

        if arguments[1:3] == ["image", "inspect"]:

            if self.image_status:
                return self.image_status

            return {
                "status": version_detector.DISCOVERY_COMPLETE,
                "stdout": json.dumps(self.images),
                "error": None
            }

        if arguments[1] == "exec":
            container_id = arguments[2]

            return self.runtime_results.get(
                container_id,
                {
                    "status": version_detector.DISCOVERY_COMPLETE,
                    "stdout": "unrecognised executable output",
                    "stderr": None,
                    "error": None
                }
            )

        if arguments[1] == "inspect":

            if self.inspect_status:
                return self.inspect_status

            return {
                "status": version_detector.DISCOVERY_COMPLETE,
                "stdout": json.dumps(self.containers),
                "error": None
            }

        raise AssertionError(f"Unexpected Docker command: {arguments}")


class ImageReferenceTests(unittest.TestCase):

    def test_normalises_docker_hub_library_images(self):
        parsed = version_detector.parse_image_reference(
            "docker.io/library/influxdb:2.7.11@sha256:abc"
        )

        self.assertEqual(parsed["repository"], "influxdb")
        self.assertEqual(parsed["tag"], "2.7.11")
        self.assertEqual(parsed["digest"], "sha256:abc")

    def test_distinguishes_registry_port_from_tag(self):
        parsed = version_detector.parse_image_reference(
            "localhost:5000/team/mosquitto"
        )

        self.assertEqual(
            parsed["repository"],
            "localhost:5000/team/mosquitto"
        )
        self.assertIsNone(parsed["tag"])

    def test_extracts_prefixed_and_suffixed_versions(self):
        self.assertEqual(
            version_detector.extract_version("ditto-things:v3.9.7"),
            "3.9.7"
        )
        self.assertEqual(
            version_detector.extract_version(
                "eclipse-mosquitto:2.1.2-alpine"
            ),
            "2.1.2"
        )
        self.assertIsNone(
            version_detector.extract_version(
                "eclipse-mosquitto:latest"
            )
        )


class SoftwareDiscoveryTests(unittest.TestCase):

    def test_multiple_mosquitto_deployments_share_component_identity(self):
        normal_id = "sha256:image-normal"
        vulnerable_id = "sha256:image-vulnerable"
        runner = FakeDockerRunner(
            containers=[
                container(
                    "c-normal",
                    "mosquitto-normal",
                    "eclipse-mosquitto:2.1.2",
                    normal_id,
                    {
                        "com.docker.compose.project": "iomt",
                        "com.docker.compose.service": "mosquitto",
                        "io.iomt.deployment": "normal"
                    }
                ),
                container(
                    "c-vulnerable",
                    "mosquitto-vulnerable",
                    "eclipse-mosquitto:1.5.5",
                    vulnerable_id,
                    {
                        "com.docker.compose.project": "iomt",
                        "com.docker.compose.service": "mosquitto",
                        "io.iomt.component": "mosquitto",
                        "io.iomt.deployment": "vulnerable-lab"
                    }
                )
            ],
            images=[
                image(
                    normal_id,
                    "eclipse-mosquitto@sha256:normal-digest"
                ),
                image(
                    vulnerable_id,
                    "eclipse-mosquitto@sha256:vulnerable-digest"
                )
            ]
        )

        result = version_detector.discover_software_instances(
            run_docker=runner
        )

        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual(len(result["instances"]), 2)
        self.assertEqual(
            {
                instance["component_id"]
                for instance in result["instances"]
            },
            {"mosquitto"}
        )
        self.assertEqual(
            {
                instance["deployment_id"]
                for instance in result["instances"]
            },
            {"normal", "vulnerable-lab"}
        )
        summaries = [
            item for item in result["components"]
            if item["component_id"] == "mosquitto"
        ]
        self.assertEqual(len(summaries), 2)
        self.assertEqual(
            {
                summary["deployment_id"]: summary["version"]
                for summary in summaries
            },
            {
                "normal": "2.1.2",
                "vulnerable-lab": "1.5.5"
            }
        )

    def test_influxdb_stores_version_digest_and_cpe_identity(self):
        image_id = "sha256:image-influxdb"
        runner = FakeDockerRunner(
            containers=[
                container(
                    "c-influx",
                    "custom-generated-name",
                    "docker.io/library/influxdb:2.7.11",
                    image_id
                )
            ],
            images=[
                image(
                    image_id,
                    "influxdb@sha256:influx-digest"
                )
            ]
        )

        result = version_detector.discover_software_instances(
            run_docker=runner
        )
        instance = result["instances"][0]

        self.assertEqual(instance["component_id"], "influxdb")
        self.assertEqual(instance["version"], "2.7.11")
        self.assertEqual(instance["image_repository"], "influxdb")
        self.assertEqual(
            instance["image_digest"],
            "sha256:influx-digest"
        )
        self.assertEqual(instance["cpe_vendor"], "influxdata")
        self.assertEqual(instance["cpe_product"], "influxdb")
        self.assertEqual(
            runner.calls[0],
            ["docker", "ps", "--quiet", "--no-trunc"]
        )

    def test_ditto_multiple_services_are_aggregated(self):
        ids = [
            "sha256:ditto-things-image",
            "sha256:ditto-gateway-image"
        ]
        runner = FakeDockerRunner(
            containers=[
                container(
                    "c-ditto-things",
                    "docker-things-1",
                    "eclipse/ditto-things:3.9.7",
                    ids[0],
                    {
                        "com.docker.compose.project": "iomt",
                        "com.docker.compose.service": "things"
                    }
                ),
                container(
                    "c-ditto-gateway",
                    "docker-gateway-1",
                    "eclipse/ditto-gateway:3.9.7",
                    ids[1],
                    {
                        "com.docker.compose.project": "iomt",
                        "com.docker.compose.service": "gateway"
                    }
                ),
                container(
                    "c-ditto-ui",
                    "docker-ditto-ui-1",
                    "eclipse/ditto-ui:3.9.7",
                    "sha256:ditto-ui-image",
                    {
                        "com.docker.compose.project": "iomt",
                        "com.docker.compose.service": "ditto-ui"
                    }
                )
            ],
            images=[
                image(
                    ids[0],
                    labels={
                        "org.opencontainers.image.version": "26.04"
                    }
                ),
                image(
                    ids[1],
                    labels={
                        "org.opencontainers.image.version": "26.04"
                    }
                ),
                image(
                    "sha256:ditto-ui-image",
                    labels={
                        "org.opencontainers.image.version": "1.31.4-alpine"
                    }
                )
            ]
        )

        dependency = version_detector.discover_software_instances(
            run_docker=runner
        )
        compatibility = version_detector.detect_versions(
            run_docker=runner
        )
        ditto_summary = next(
            item for item in dependency["components"]
            if item["component_id"] == "ditto"
        )

        self.assertEqual(ditto_summary["status"], "DETECTED")
        self.assertEqual(ditto_summary["version"], "3.9.7")
        self.assertEqual(len(ditto_summary["instance_ids"]), 3)
        self.assertEqual(
            compatibility["Eclipse Ditto"]["status"],
            "Detected"
        )
        self.assertEqual(
            compatibility["Eclipse Ditto"]["version"],
            "3.9.7"
        )
        self.assertEqual(
            len(compatibility["Eclipse Ditto"]["services"]),
            3
        )
        self.assertEqual(
            {
                service["oci_version_label"]
                for service in compatibility[
                    "Eclipse Ditto"
                ]["services"]
            },
            {"26.04", "1.31.4-alpine"}
        )
        self.assertEqual(
            {
                service["version_source"]
                for service in compatibility[
                    "Eclipse Ditto"
                ]["services"]
            },
            {"image_tag"}
        )
        self.assertTrue(
            all(
                service["image_id"]
                for service in compatibility[
                    "Eclipse Ditto"
                ]["services"]
            )
        )
        self.assertIn(
            "image_repository",
            compatibility["Eclipse Ditto"][
                "classification_source"
            ]
        )

    def test_ditto_mixed_versions_are_reported_without_guessing(self):
        ids = ["sha256:ditto-a", "sha256:ditto-b"]
        runner = FakeDockerRunner(
            containers=[
                container(
                    "c-a",
                    "ditto-things",
                    "eclipse/ditto-things:3.9.7",
                    ids[0],
                    {
                        "com.docker.compose.project": "iomt",
                        "com.docker.compose.service": "things"
                    }
                ),
                container(
                    "c-b",
                    "ditto-gateway",
                    "eclipse/ditto-gateway:3.9.6",
                    ids[1],
                    {
                        "com.docker.compose.project": "iomt",
                        "com.docker.compose.service": "gateway"
                    }
                )
            ],
            images=[image(ids[0]), image(ids[1])]
        )

        result = version_detector.discover_software_instances(
            run_docker=runner
        )
        compatibility = version_detector.detect_versions(
            run_docker=runner
        )
        summary = next(
            item for item in result["components"]
            if item["component_id"] == "ditto"
        )

        self.assertEqual(summary["status"], "MIXED")
        self.assertIsNone(summary["version"])
        self.assertEqual(
            summary["versions"],
            ["3.9.6", "3.9.7"]
        )
        self.assertEqual(
            compatibility["Eclipse Ditto"]["status"],
            "MIXED"
        )
        self.assertIsNone(
            compatibility["Eclipse Ditto"]["version"]
        )

    def test_unknown_repository_requires_supporting_component_label(self):
        image_id = "sha256:efrecon"
        without_label = FakeDockerRunner(
            containers=[
                container(
                    "c-1",
                    "mqtt",
                    "efrecon/mosquitto:1.5.5",
                    image_id
                )
            ],
            images=[image(image_id)]
        )
        with_label = FakeDockerRunner(
            containers=[
                container(
                    "c-1",
                    "mqtt",
                    "efrecon/mosquitto:1.5.5",
                    image_id,
                    {
                        "io.iomt.component": "mosquitto",
                        "io.iomt.deployment": "vulnerable-lab"
                    }
                )
            ],
            images=[image(image_id)]
        )

        unsupported = version_detector.discover_software_instances(
            run_docker=without_label
        )
        supported = version_detector.discover_software_instances(
            run_docker=with_label
        )

        self.assertIsNone(
            unsupported["instances"][0]["component_id"]
        )
        self.assertEqual(
            supported["instances"][0]["component_id"],
            "mosquitto"
        )
        self.assertEqual(
            supported["instances"][0]["deployment_id"],
            "vulnerable-lab"
        )
        self.assertEqual(
            supported["instances"][0]["image_repository"],
            "efrecon/mosquitto"
        )
        self.assertEqual(
            supported["instances"][0]["cpe_product"],
            "mosquitto"
        )

    def test_unknown_repository_with_service_metadata_is_ambiguous(self):
        image_id = "sha256:ambiguous"
        runner = FakeDockerRunner(
            containers=[
                container(
                    "c-1",
                    "mqtt",
                    "example/mosquitto:1.5.5",
                    image_id,
                    {
                        "com.docker.compose.service": "mosquitto"
                    }
                )
            ],
            images=[image(image_id)]
        )

        result = version_detector.discover_software_instances(
            run_docker=runner
        )
        instance = result["instances"][0]

        self.assertIsNone(instance["component_id"])
        self.assertEqual(instance["status"], "AMBIGUOUS")

    def test_mosquitto_runtime_probe_establishes_unrecognised_image_identity(self):
        image_id = "sha256:efrecon"
        runner = FakeDockerRunner(
            containers=[
                container(
                    "c-mosquitto-lab",
                    "mosquitto-vuln-lab",
                    "efrecon/mosquitto:1.5.5",
                    image_id
                )
            ],
            images=[
                image(
                    image_id,
                    "efrecon/mosquitto@sha256:verified-digest"
                )
            ],
            runtime_results={
                "c-mosquitto-lab": {
                    "status": version_detector.DISCOVERY_COMPLETE,
                    "stdout": "mosquitto version 1.5.5\n",
                    "stderr": None,
                    "error": None
                }
            }
        )

        result = version_detector.discover_software_instances(
            run_docker=runner
        )
        instance = result["instances"][0]

        self.assertEqual(instance["component_id"], "mosquitto")
        self.assertEqual(instance["deployment_id"], "mosquitto-vuln-lab")
        self.assertEqual(instance["version"], "1.5.5")
        self.assertEqual(instance["version_source"], "runtime_probe")
        self.assertEqual(
            instance["image_repository"],
            "efrecon/mosquitto"
        )
        self.assertEqual(
            instance["image_digest"],
            "sha256:verified-digest"
        )
        self.assertIn(
            "runtime_probe_product",
            instance["classification_source"]
        )
        self.assertTrue(instance["cpe_identity_usable"])
        self.assertEqual(
            instance["application_version_evidence"]["runtime"],
            "1.5.5"
        )
        self.assertIn(
            ["docker", "exec", "c-mosquitto-lab", "mosquitto", "-h"],
            runner.calls
        )

    def test_mosquitto_runtime_probe_failure_preserves_tag_identity(self):
        image_id = "sha256:mosquitto"
        runner = FakeDockerRunner(
            containers=[
                container(
                    "c-mosquitto",
                    "mosquitto",
                    "eclipse-mosquitto:2.1.2",
                    image_id
                )
            ],
            images=[image(image_id)],
            runtime_results={
                "c-mosquitto": {
                    "status": version_detector.DOCKER_ERROR,
                    "stdout": None,
                    "stderr": "mosquitto executable unavailable",
                    "error": "exec failed"
                }
            }
        )

        result = version_detector.discover_software_instances(
            run_docker=runner
        )
        instance = result["instances"][0]

        self.assertEqual(instance["component_id"], "mosquitto")
        self.assertEqual(instance["version"], "2.1.2")
        self.assertEqual(instance["version_source"], "image_tag")
        self.assertEqual(
            instance["runtime_probe"]["status"],
            "COMMAND_FAILED"
        )

    def test_mosquitto_runtime_mismatch_is_preserved_as_conflict(self):
        image_id = "sha256:mosquitto-mismatch"
        runner = FakeDockerRunner(
            containers=[
                container(
                    "c-mosquitto",
                    "mosquitto",
                    "eclipse-mosquitto:2.1.2",
                    image_id
                )
            ],
            images=[image(image_id)],
            runtime_results={
                "c-mosquitto": {
                    "status": version_detector.DISCOVERY_COMPLETE,
                    "stdout": "mosquitto version 1.5.5\n",
                    "stderr": None,
                    "error": None
                }
            }
        )

        result = version_detector.discover_software_instances(
            run_docker=runner
        )
        instance = result["instances"][0]

        self.assertEqual(
            instance["status"],
            "VERSION_CONFLICT"
        )
        self.assertIsNone(instance["version"])
        self.assertEqual(
            instance["application_version_evidence"],
            {
                "image_tag": "2.1.2",
                "container_io_iomt_version": None,
                "image_io_iomt_version": None,
                "runtime": "1.5.5"
            }
        )

    def test_mosquitto_runtime_unrecognised_output_does_not_establish_identity(self):
        image_id = "sha256:efrecon-unrecognised"
        runner = FakeDockerRunner(
            containers=[
                container(
                    "c-mosquitto",
                    "mosquitto-vuln-lab",
                    "efrecon/mosquitto:1.5.5",
                    image_id
                )
            ],
            images=[image(image_id)],
            runtime_results={
                "c-mosquitto": {
                    "status": version_detector.DISCOVERY_COMPLETE,
                    "stdout": "another broker service\n",
                    "stderr": None,
                    "error": None
                }
            }
        )

        result = version_detector.discover_software_instances(
            run_docker=runner
        )
        instance = result["instances"][0]

        self.assertIsNone(instance["component_id"])
        self.assertEqual(instance["status"], "VERSION_UNKNOWN")
        self.assertEqual(
            instance["runtime_probe"]["status"],
            "UNRECOGNISED_OUTPUT"
        )
        self.assertFalse(instance["cpe_identity_usable"])

    def test_image_metadata_failure_makes_component_partial(self):
        runner = FakeDockerRunner(
            containers=[
                container(
                    "c-influx",
                    "influx",
                    "influxdb:2.7.11",
                    "sha256:influx"
                )
            ],
            images=[],
            image_status={
                "status": version_detector.DOCKER_ERROR,
                "stdout": None,
                "error": "image inspect failed"
            }
        )

        result = version_detector.discover_software_instances(
            run_docker=runner
        )
        summary = next(
            item for item in result["components"]
            if item["component_id"] == "influxdb"
        )

        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(
            result["instances"][0]["status"],
            "PARTIAL"
        )
        self.assertEqual(summary["status"], "PARTIAL")

    def test_latest_is_unknown_and_explicit_application_conflict_is_explicit(self):
        ids = ["sha256:latest", "sha256:conflict"]
        runner = FakeDockerRunner(
            containers=[
                container(
                    "c-latest",
                    "mosq-latest",
                    "eclipse-mosquitto:latest",
                    ids[0]
                ),
                container(
                    "c-conflict",
                    "mosq-conflict",
                    "eclipse-mosquitto:2.1.2",
                    ids[1],
                    {"io.iomt.version": "2.1.3"}
                )
            ],
            images=[
                image(ids[0]),
                image(ids[1])
            ]
        )

        result = version_detector.discover_software_instances(
            run_docker=runner
        )

        self.assertEqual(
            result["instances"][0]["status"],
            "VERSION_UNKNOWN"
        )
        self.assertIsNone(result["instances"][0]["version"])
        self.assertEqual(
            result["instances"][1]["status"],
            "VERSION_CONFLICT"
        )
        self.assertIsNone(result["instances"][1]["version"])

    def test_base_image_label_does_not_conflict_with_application_tag(self):
        image_id = "sha256:ditto-base-label"
        runner = FakeDockerRunner(
            containers=[
                container(
                    "c-ditto",
                    "ditto-things",
                    "eclipse/ditto-things:3.9.7",
                    image_id
                )
            ],
            images=[
                image(
                    image_id,
                    labels={
                        "org.opencontainers.image.version": "26.04"
                    }
                )
            ]
        )

        result = version_detector.discover_software_instances(
            run_docker=runner
        )
        instance = result["instances"][0]

        self.assertEqual(instance["version"], "3.9.7")
        self.assertEqual(instance["status"], "DETECTED")
        self.assertEqual(instance["oci_version_label"], "26.04")

    def test_compatibility_adapter_preserves_multiple_deployments(self):
        ids = ["sha256:mosq-a", "sha256:mosq-b"]
        runner = FakeDockerRunner(
            containers=[
                container(
                    "c-a",
                    "mosquitto-normal",
                    "eclipse-mosquitto:2.1.2",
                    ids[0],
                    {
                        "io.iomt.component": "mosquitto",
                        "io.iomt.deployment": "normal",
                        "io.iomt.display_name": "Mosquitto"
                    }
                ),
                container(
                    "c-b",
                    "mosquitto-vuln",
                    "eclipse-mosquitto:1.5.5",
                    ids[1],
                    {
                        "io.iomt.component": "mosquitto",
                        "io.iomt.deployment": "vulnerable",
                        "io.iomt.display_name": "Mosquitto Vulnerable Lab"
                    }
                )
            ],
            images=[image(ids[0]), image(ids[1])]
        )

        detected = version_detector.detect_versions(
            run_docker=runner
        )
        mosquitto_records = [
            record
            for record in detected.values()
            if record.get("component_id") == "mosquitto"
        ]

        self.assertEqual(len(mosquitto_records), 2)
        self.assertEqual(
            {
                record["deployment_id"]
                for record in mosquitto_records
            },
            {"normal", "vulnerable"}
        )
        self.assertEqual(
            {
                record["version"]
                for record in mosquitto_records
            },
            {"1.5.5", "2.1.2"}
        )
        self.assertTrue(
            all(
                record["status"] == "Detected"
                for record in mosquitto_records
            )
        )

    def test_compatibility_adapter_exposes_unclassified_deployments(self):
        image_id = "sha256:efrecon"
        runner = FakeDockerRunner(
            containers=[
                container(
                    "c-normal",
                    "mosquitto",
                    "eclipse-mosquitto:2.1.2",
                    "sha256:normal"
                ),
                container(
                    "c-lab",
                    "mosquitto-vuln-lab",
                    "efrecon/mosquitto:1.5.5",
                    image_id
                )
            ],
            images=[
                image("sha256:normal"),
                image(image_id)
            ]
        )

        detected = version_detector.detect_versions(
            run_docker=runner
        )
        diagnostics = {
            key: record
            for key, record in detected.items()
            if record.get("diagnostic")
        }

        self.assertTrue(
            any(
                record["status"] == "UNCLASSIFIED"
                and record["version"] == "1.5.5"
                and record["image"]
                == "efrecon/mosquitto:1.5.5"
                for record in diagnostics.values()
            )
        )


class DockerFailureTests(unittest.TestCase):

    def _failure(self, status):
        runner = FakeDockerRunner(
            containers=[],
            images=[],
            ps_status={
                "status": status,
                "stdout": None,
                "error": status
            }
        )

        discovery = version_detector.discover_software_instances(
            run_docker=runner
        )
        compatibility = version_detector.detect_versions(
            run_docker=runner
        )

        self.assertEqual(discovery["status"], status)
        self.assertEqual(discovery["instances"], [])
        self.assertTrue(
            all(
                record["status"] == status
                for record in compatibility.values()
            )
        )

    def test_docker_unavailable(self):
        self._failure(version_detector.DOCKER_UNAVAILABLE)

    def test_docker_timeout(self):
        self._failure(version_detector.DOCKER_TIMEOUT)

    def test_docker_error(self):
        self._failure(version_detector.DOCKER_ERROR)

    def test_malformed_container_output(self):
        runner = FakeDockerRunner(
            containers=[
                container(
                    "c-1",
                    "unknown",
                    "example/unknown:1.0.0",
                    "sha256:image"
                )
            ],
            images=[],
            inspect_status={
                "status": version_detector.DISCOVERY_COMPLETE,
                "stdout": "not-json",
                "error": None
            }
        )

        result = version_detector.discover_software_instances(
            run_docker=runner
        )

        self.assertEqual(result["status"], "MALFORMED_OUTPUT")
        self.assertEqual(result["instances"], [])

    def test_malformed_individual_container_is_reported(self):
        runner = FakeDockerRunner(
            containers=[
                {
                    "Id": "c-malformed",
                    "Name": "/malformed",
                    "Image": "sha256:malformed-image",
                    "Config": "not-an-object"
                }
            ],
            images=[]
        )

        result = version_detector.discover_software_instances(
            run_docker=runner
        )

        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(len(result["unclassified"]), 1)

    def test_run_docker_handles_missing_executable(self):
        with patch.object(
            version_detector.subprocess,
            "run",
            side_effect=FileNotFoundError
        ):
            result = version_detector._run_docker(
                ["docker", "ps"]
            )

        self.assertEqual(result["status"], "DOCKER_UNAVAILABLE")

    def test_run_docker_handles_timeout(self):
        with patch.object(
            version_detector.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired("docker", 10)
        ):
            result = version_detector._run_docker(
                ["docker", "ps"]
            )

        self.assertEqual(result["status"], "DOCKER_TIMEOUT")

    def test_no_running_containers_is_complete_empty(self):
        runner = FakeDockerRunner([], [])

        result = version_detector.discover_software_instances(
            run_docker=runner
        )

        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual(result["instances"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
