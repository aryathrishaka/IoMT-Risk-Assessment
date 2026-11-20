"""Derive the v9 experimental assessment using only saved evidence."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
V8_PATH = ROOT / "scenarios/ebsr_cve_2018_12546_experiment_v8.json"
OUTPUT_PATH = ROOT / "scenarios/ebsr_cve_2018_12546_experiment_v9.json"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def build_bundle():
    document = load(V8_PATH)
    sources = {
        key: ROOT / document["evidence_provenance"][key]
        for key in ("experiment_1", "experiment_2", "readback_verification")
    }
    for key, path in sources.items():
        if sha256(path) != document["source_hashes"][key]:
            raise ValueError(f"Saved evidence hash mismatch for {key}")
    if sha256(ROOT / "ebsr.py") != document["source_hashes"]["ebsr"]:
        raise ValueError("The frozen evaluator hash differs from v8")

    exp1, exp2, readback = (load(path) for path in sources.values())
    if (readback["status"] != "CONFIRMED"
            or not all(readback["checks"].values())
            or readback["source_evidence"]["sha256"] != sha256(sources["experiment_2"])):
        raise ValueError("Readback does not confirm the saved Experiment 2 evidence")

    source_paths = {key: path.relative_to(ROOT).as_posix() for key, path in sources.items()}
    run_windows = {
        1: {"start": exp1["run_started_utc"], "stop": exp1["run_finished_utc"]},
        2: {"start": exp2["started_utc"], "stop": exp2["finished_utc"]},
    }
    evidence = {item["proposition_id"]: item for item in document["evidence"]}
    document["assessment_version"] = "research-cve-2018-12546-experiment-v9"
    document["derived_from"] = {"path": V8_PATH.relative_to(ROOT).as_posix(), "sha256": sha256(V8_PATH)}
    document["source_hashes"].update(v8_scenario=sha256(V8_PATH), adapter=sha256(ROOT / "ebsr_adapter.py"))
    document["evidence_provenance"]["v8_scenario"] = document["derived_from"]["path"]
    document["condition_semantics"]["Y"] = (
        "Receiver processing and controls for the tested event. On the direct broker "
        "transition the authorized retained replacement verifies subscriber-side access; "
        "publisher-source checking belongs to broker K. Downstream Y requires evidence "
        "of processing or receiver control for the affected event."
    )

    for arm in ("vulnerable", "control"):
        profile = next(p for p in document["attacker_profiles"] if p["attacker_id"].endswith(arm.upper()))
        document["attacker_profiles"].append({
            **profile,
            "attacker_id": profile["attacker_id"].replace("EXP2", "EXP1"),
            "provenance": source_paths["experiment_1"],
        })

    for scenario in document["scenarios"]:
        sid = scenario["scenario_id"]
        number = int(sid[3])
        arm = "control" if "-CONTROL-" in sid else "vulnerable"
        run = exp1 if number == 1 else exp2
        capture = run["arms"][arm]
        if number == 1:
            scenario["attacker_id"] = scenario["attacker_id"].replace("EXP2", "EXP1")
        for path in scenario["paths"]:
            source_id = path["transitions"][0]["source_deployment_id"]
            if source_id != capture["deployment"]["container_name"]:
                raise ValueError(f"Experiment source identity mismatch in {sid}")
            observation = {
                "cve_id": "CVE-2018-12546",
                "source_observation_grade": (
                    "CONTROL_BEHAVIOUR_OBSERVED" if arm == "control" else "INDEPENDENTLY_REPRODUCED"
                ),
                "downstream_targets": {},
            }
            path["experimental_observation"] = observation
            for transition in path["transitions"]:
                target = transition["target_deployment_id"]
                is_storage = target == "influxdb-lab"
                artifact = f"experiment_{number}"
                scope = {
                    "run_id": run["run_id"],
                    "observation_window_utc": run_windows[number],
                    "experiment_broker_id": source_id,
                    "source_deployment_id": transition["source_deployment_id"],
                    "target_deployment_id": target,
                    "transition_type": transition["transition_type"],
                    "attacker_id": scenario["attacker_id"],
                }
                if number == 2:
                    marker = readback[f"{arm}_retained_marker"]
                    retained = capture["retained"]
                    if (marker["thing_id"] != capture["thing_id"]
                            or marker["run_marker"] != retained["stored_message_check"]["marker"]):
                        raise ValueError(f"Readback event identity mismatch in {sid}")
                    scope.update(thing_id=marker["thing_id"], run_marker=marker["run_marker"])
                    window = {
                        "start": retained["downstream_observation"]["open_started_utc"],
                        "stop": capture["finished_utc"],
                    }
                    if arm == "control":
                        window = readback["control_retained_marker"]["retained_observation_window"]
                    if is_storage and arm == "control":
                        window = readback["control_window_support"]["window"]
                    observation["downstream_targets"][target] = {
                        "cve_specific_testing": (
                            "UPSTREAM_WITHHELD_NO_TARGET_EFFECT_OBSERVED" if arm == "control"
                            else "CVE_EFFECT_OBSERVED"
                        ),
                        "normal_path_testing": "VERIFIED",
                        "observation_window_utc": window,
                        "supporting_artifact": source_paths["readback_verification" if is_storage else artifact],
                        "thing_id": marker["thing_id"],
                        "run_marker": marker["run_marker"],
                    }

                for variable, binding in transition["conditions"].items():
                    item = evidence[binding["proposition_id"]]
                    if item["proposition_id"].startswith("unresolved."):
                        continue
                    item.update(scope)
                    item["supporting_artifact"] = source_paths[artifact]
                    if is_storage and variable in {"B", "Y"}:
                        item["supporting_artifact"] = source_paths["readback_verification"]
                    if variable == "A":
                        item["evidence"] = [
                            f"The experiment captured Mosquitto runtime version {capture['deployment']['runtime_version']}.",
                            "The saved affected range ends at 1.5.5 inclusive.",
                        ]
                        item["applicability_reference"] = "scenarios/ebsr_mosquitto_12546_12550_12551_v7.json"
                        item["source"] = source_paths[artifact]
                    if arm == "control" and variable == "Y":
                        if number == 1:
                            if not capture["subscriber_control"]["replacement_marker_delivered"]:
                                raise ValueError("Direct subscriber control was not verified")
                            item.update(
                                status="T",
                                evidence=["An authorized retained replacement reached a fresh subscriber on the tested topic."],
                                reason="Subscriber-side read and retained receipt were operational.",
                            )
                        else:
                            item.update(
                                status="U",
                                evidence=["The receiver processed normal and authorized post-control traffic."],
                                reason="The broker withheld the affected event, leaving event-specific receiver handling untested.",
                            )
                    if is_storage and arm == "control" and variable == "K":
                        item.update(
                            status="U",
                            evidence=["Normal and post-control events exercised the writer and database path."],
                            reason="The affected event was withheld before Ditto, leaving its carriage on this transition untested.",
                        )
                if number == 2:
                    prefix = f"target.2018_12546.exp2.{arm}.{'influxdb' if is_storage else 'ditto'}"
                    impact = evidence[f"{prefix}.I"]
                    impact.update(scope)
                    impact["observation_window_utc"] = window
                    impact["source"] = source_paths["readback_verification" if is_storage else artifact]
                    impact["supporting_artifact"] = impact["source"]
                    if is_storage and arm == "vulnerable":
                        impact["evidence"] = ["CSV readback confirmed two matching retained-marker records at distinct timestamps."]

    for record in document["validation_records"]:
        record["evidence"] = [source_paths["experiment_2"]]
    document["experiment_reproduction_scope"]["control"]["downstream_cve_specific_observation"] = (
        "UPSTREAM_WITHHELD_NO_TARGET_EFFECT_OBSERVED"
    )
    document["saved_experimental_assessment"] = {
        "temporary_deployments_currently_present": False,
        "assessment_uses_saved_evidence": True,
        "baseline_transfer": "NOT_PERFORMED",
    }
    document["cve_free_transition_limitation"] = {
        "A": "UNKNOWN", "G": "UNKNOWN",
        "reason": "The frozen material leaves A and G undefined for the CVE-free Ditto-to-InfluxDB step.",
        "readback_status": "CONFIRMED",
    }
    for item in evidence.values():
        artifact = item.get("supporting_artifact")
        if artifact:
            item["supporting_artifact_sha256"] = sha256(ROOT / artifact)
    return document


def main():
    document = build_bundle()
    content = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if OUTPUT_PATH.exists():
        if OUTPUT_PATH.read_bytes() != content:
            raise FileExistsError(f"Preserve the existing bundle before rebuilding: {OUTPUT_PATH}")
    else:
        OUTPUT_PATH.write_bytes(content)
    return OUTPUT_PATH


if __name__ == "__main__":
    print(main())

