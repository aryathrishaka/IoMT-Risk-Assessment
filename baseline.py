# ---------------------------------------------------------
# CVSS-only baseline
# ---------------------------------------------------------
# Docker versions -> NVD CVEs -> applicability -> CVSS ranking
#
# This is the comparison point for the architecture-aware model.
# It deliberately uses NO architecture or deployment context:
# a component's baseline risk is just its CVEs sorted by CVSS.
#
# CVSS policy (see applicability.py): ranking uses the primary scale,
# CVSS v3.x, only. Affected CVEs with no v3.x score are kept in a
# separate group ("other scale") with their v4.0 / v2.0 scores shown.
# Scores from different CVSS versions are never mixed in one ranking.
#
# Output: baseline_assessment_results.json by default
#
# Usage:
#   python baseline.py
#   python baseline.py --set "Eclipse Ditto=3.6.0"     # manual version
#   python baseline.py --only Mosquitto
# ---------------------------------------------------------

import argparse
import json

from applicability import (
    AFFECTED,
    UNKNOWN,
    TARGETS,
    PRIMARY_SCALE_LABEL,
    cvss_summary,
    evaluate_applicability,
    resolve_component_id,
)


def cve_id_and_description(cve_item):
    cve = cve_item.get("cve", {})
    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break
    return cve.get("id", "UNKNOWN-ID"), description


def build_component_baseline(
    component,
    version,
    candidates,
    component_id=None,
    discovery_evidence=None,
    retrieval=None,
    environment=None,
    assessment_version_source=None,
):
    """
    Classify candidate CVEs for one component and rank the affected ones.
    Pure function: no network, easy to test.
    """

    affected, unknown, not_affected = [], [], []
    applicability_results = []
    canonical_id = component_id or resolve_component_id(component)

    for item in candidates:
        applicability = evaluate_applicability(
            item,
            canonical_id or component,
            version,
            environment
        )
        status = applicability["status"]
        reason = applicability["reason"]
        cve_id, description = cve_id_and_description(item)

        row = {
            "cve_id": cve_id,
            "status": status,
            "reason": reason,
            "cvss": cvss_summary(item),
            "description": description[:200],
            "applicability": applicability,
        }
        applicability_results.append(applicability)

        if status == AFFECTED:
            affected.append(row)
        elif status == UNKNOWN:
            unknown.append(row)
        else:
            not_affected.append(row)

    def ranked_key(row):
        # primary-scale score only
        return (-row["cvss"]["primary"]["score"], row["cve_id"])

    def other_scale_key(row):
        # Group order only: v4.0 block, then v2.0 block, then unscored.
        # Never compared across scales within the ranking.
        others = [e for e in row["cvss"]["other"] if e["score"] is not None]
        if not others:
            return (2, 0, row["cve_id"])
        best = min(others, key=lambda e: {"4.0": 0, "2.0": 1}.get(e["version"], 2))
        block = {"4.0": 0, "2.0": 1}.get(best["version"], 2)
        return (block, -best["score"], row["cve_id"])

    def split(rows):
        scored = sorted((r for r in rows if r["cvss"]["primary"]), key=ranked_key)
        other = sorted((r for r in rows if not r["cvss"]["primary"]),
                       key=other_scale_key)
        return scored, other

    affected_ranked, affected_other = split(affected)
    unknown_ranked, unknown_other = split(unknown)
    not_affected.sort(key=lambda row: row["cve_id"])
    retrieval_status = (
        retrieval.get("status")
        if retrieval
        else None
    )
    affected_count = len(affected_ranked) + len(affected_other)
    detected_version = (
        discovery_evidence.get("version")
        if discovery_evidence
        else None
    )
    version_override = (
        assessment_version_source == "manual_override"
        if assessment_version_source is not None
        else (
            detected_version is not None
            and str(detected_version) != str(version)
        )
    )
    assessment_performed = retrieval_status not in (
        "FAILED",
        "MALFORMED",
    )

    if retrieval_status in ("FAILED", "MALFORMED"):
        no_confirmed_affected = None
    elif (
        retrieval_status == "PARTIAL"
        and len(candidates) == 0
    ):
        no_confirmed_affected = None
    else:
        no_confirmed_affected = affected_count == 0

    return {
        "component": component,
        "component_id": canonical_id,
        "deployment_id": (
            discovery_evidence.get("deployment_id")
            if discovery_evidence
            else None
        ),
        "version": version,
        "detected_version": detected_version,
        "version_override": (
            version_override
            if discovery_evidence
            else None
        ),
        "assessment_version_source": (
            assessment_version_source
            or (
                "manual_override"
                if version_override
                else (
                    discovery_evidence.get("version_source")
                    if discovery_evidence
                    else "caller_supplied"
                )
            )
        ),
        "primary_scale": PRIMARY_SCALE_LABEL,
        "candidates": len(candidates),
        "affected": affected_ranked,
        "affected_other_scale": affected_other,
        "unknown": unknown_ranked + unknown_other,
        "unknown_count": len(unknown_ranked) + len(unknown_other),
        "not_affected": not_affected,
        "not_affected_count": len(not_affected),
        "applicability": applicability_results,
        "retrieval": retrieval,
        "retrieval_complete": (
            retrieval_status == "COMPLETE"
            if retrieval_status is not None
            else None
        ),
        "assessment_performed": assessment_performed,
        "no_confirmed_affected_in_retrieved_candidates": (
            no_confirmed_affected
            if assessment_performed
            else None
        ),
        "discovery_evidence": discovery_evidence,
    }


def print_component(result):
    print()
    print(f"{result['component']}  (version {result['version']})")
    print("-" * 60)
    print(
        f"candidates={result['candidates']}  "
        f"affected={len(result['affected']) + len(result['affected_other_scale'])}  "
        f"unknown={len(result['unknown'])}  "
        f"not affected={result['not_affected_count']}"
    )

    retrieval = result.get("retrieval")

    if retrieval:
        print(f"retrieval status={retrieval.get('status')}")

        if retrieval.get("error"):
            print(f"retrieval error={retrieval['error']}")

    if result["affected"]:
        print()
        print(f"Baseline ranking (CVSS only, {result['primary_scale']}):")
        for rank, row in enumerate(result["affected"], start=1):
            p = row["cvss"]["primary"]
            print(
                f"  {rank:>2}. {row['cve_id']:<16} "
                f"{str(p['score']):>4}  {str(p['severity'] or ''):<8} "
                f"(CVSS {p['version']})"
            )

    if result["affected_other_scale"]:
        print()
        print(f"Affected, no {result['primary_scale']} score "
              "(not ranked, scores on other scales shown):")
        for row in result["affected_other_scale"]:
            shown = ", ".join(
                f"v{e['version']}={e['score']}"
                for e in row["cvss"]["other"] if e["score"] is not None
            ) or "no CVSS score"
            print(f"      {row['cve_id']:<16} {shown}")

    if result["unknown"]:
        print()
        print("Needs manual check (applicability UNKNOWN):")
        for row in result["unknown"]:
            print(f"      {row['cve_id']:<16} {row['reason']}")


def parse_overrides(pairs):
    overrides = {}
    for pair in pairs or []:
        name, _, version = pair.partition("=")
        if not version:
            raise SystemExit(f'Bad --set value "{pair}", use "Component=version".')
        overrides[name.strip()] = version.strip()
    return overrides


def selection_matches(value, selection, info):
    """Match --only against deployment, product or architecture identity."""

    if not value:
        return True

    expected = value.strip().casefold()
    candidates = {
        selection,
        info.get("display_name"),
        info.get("component_id"),
        info.get("architecture_component"),
    }

    return any(
        isinstance(candidate, str)
        and candidate.casefold() == expected
        for candidate in candidates
    )


def get_version_override(selection, info, overrides):
    """Resolve an override by exact deployment before broader identities."""

    for key in (
        selection,
        info.get("display_name"),
        info.get("component_id"),
        info.get("architecture_component"),
    ):
        if key and key in overrides:
            return overrides[key]

    return None


def skipped_result(selection, info, reason):
    """Preserve discovery evidence when a deployment cannot be assessed."""

    return {
        "component": selection,
        "component_id": info.get("component_id"),
        "deployment_id": info.get("deployment_id"),
        "version": info.get("version"),
        "primary_scale": PRIMARY_SCALE_LABEL,
        "candidates": 0,
        "affected": [],
        "affected_other_scale": [],
        "unknown": [],
        "not_affected": [],
        "not_affected_count": 0,
        "applicability": [],
        "retrieval": None,
        "retrieval_complete": None,
        "assessment_performed": False,
        "no_confirmed_affected_in_retrieved_candidates": None,
        "unknown_count": 0,
        "detected_version": info.get("version"),
        "version_override": None,
        "assessment_version_source": None,
        "discovery_evidence": info,
        "status": "SKIPPED",
        "skip_reason": reason,
    }


def main():
    parser = argparse.ArgumentParser(description="CVSS-only baseline")
    parser.add_argument("--set", action="append", metavar="COMPONENT=VERSION",
                        help="manual version (e.g. for images tagged 'latest')")
    parser.add_argument("--only", help="run a single component")
    parser.add_argument(
        "--out",
        default="baseline_assessment_results.json"
    )
    args = parser.parse_args()

    # Imported here so the pure functions above can be tested
    # without Docker or network access.
    from version_detector import detect_versions
    from nvd_api import search_cves_by_keyword_with_status

    overrides = parse_overrides(args.set)
    detected = detect_versions()

    results = []

    for selection, info in detected.items():

        if not selection_matches(args.only, selection, info):
            continue

        if info.get("diagnostic"):
            result = skipped_result(
                selection,
                info,
                info.get("reason")
                or info.get("error")
                or info.get("status")
                or "Discovery evidence unavailable."
            )
            print_component(result)
            results.append(result)
            continue

        override_version = get_version_override(
            selection,
            info,
            overrides
        )
        version = override_version or info.get("version")

        if not version or version == "latest":
            print()
            print(f"{selection}: no usable version "
                  f"(detected: {version}). Skipped.")
            print(f'   Provide one with: --set "{selection}=<version>"')
            results.append(
                skipped_result(
                    selection,
                    info,
                    "No usable detected version."
                )
            )
            continue

        component_id = (
            info.get("component_id")
            or resolve_component_id(selection)
        )
        keyword = info.get("nvd_search_term")

        if not keyword:
            target = TARGETS.get(info.get("display_name"))
            keyword = target[1] if target else None

        if not component_id or not keyword:
            results.append(
                skipped_result(
                    selection,
                    info,
                    "Canonical CPE identity or NVD search term unavailable."
                )
            )
            continue

        print()
        print(f"Querying NVD for {selection} ({keyword}) ...")
        retrieval = search_cves_by_keyword_with_status(
            keyword,
            results_per_page=100
        )
        candidates = retrieval["items"]
        retrieval_summary = {
            "status": retrieval["status"],
            "received": retrieval["received"],
            "total_results": retrieval["total_results"],
            "error": retrieval["error"],
        }

        result = build_component_baseline(
            selection,
            version,
            candidates,
            component_id=component_id,
            discovery_evidence=info,
            retrieval=retrieval_summary,
            assessment_version_source=(
                "manual_override"
                if override_version is not None
                else info.get("version_source")
            )
        )
        print_component(result)
        results.append(result)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print()
    print(f"Saved {args.out}")


if __name__ == "__main__":
    main()
