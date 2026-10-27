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
# Output: baseline_results.json (read by the later risk stage)
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
    determine_applicability,
)


def cve_id_and_description(cve_item):
    cve = cve_item.get("cve", {})
    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break
    return cve.get("id", "UNKNOWN-ID"), description


def build_component_baseline(component, version, candidates):
    """
    Classify candidate CVEs for one component and rank the affected ones.
    Pure function: no network, easy to test.
    """

    affected, unknown, excluded = [], [], 0

    for item in candidates:
        status, reason = determine_applicability(item, component, version)
        cve_id, description = cve_id_and_description(item)

        row = {
            "cve_id": cve_id,
            "status": status,
            "reason": reason,
            "cvss": cvss_summary(item),
            "description": description[:200],
        }

        if status == AFFECTED:
            affected.append(row)
        elif status == UNKNOWN:
            unknown.append(row)
        else:
            excluded += 1

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

    return {
        "component": component,
        "version": version,
        "primary_scale": PRIMARY_SCALE_LABEL,
        "candidates": len(candidates),
        "affected": affected_ranked,
        "affected_other_scale": affected_other,
        "unknown": unknown_ranked + unknown_other,
        "not_affected_count": excluded,
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


def main():
    parser = argparse.ArgumentParser(description="CVSS-only baseline")
    parser.add_argument("--set", action="append", metavar="COMPONENT=VERSION",
                        help="manual version (e.g. for images tagged 'latest')")
    parser.add_argument("--only", help="run a single component")
    parser.add_argument("--out", default="baseline_results.json")
    args = parser.parse_args()

    # Imported here so the pure functions above can be tested
    # without Docker or network access.
    from version_detector import detect_versions
    from nvd_api import search_cves_by_keyword

    overrides = parse_overrides(args.set)
    detected = detect_versions()

    results = []

    for component in TARGETS:
        if args.only and component != args.only:
            continue

        info = detected.get(component, {})
        version = overrides.get(component) or info.get("version")

        if not version or version == "latest":
            print()
            print(f"{component}: no usable version "
                  f"(detected: {version}). Skipped.")
            print(f'   Provide one with: --set "{component}=<version>"')
            continue

        keyword = TARGETS[component][1]
        print()
        print(f"Querying NVD for {component} ({keyword}) ...")
        candidates = search_cves_by_keyword(keyword, results_per_page=100)

        result = build_component_baseline(component, version, candidates)
        print_component(result)
        results.append(result)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print()
    print(f"Saved {args.out}")


if __name__ == "__main__":
    main()
