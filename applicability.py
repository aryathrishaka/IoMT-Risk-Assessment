# ---------------------------------------------------------
# Applicability and CVSS policy for the baseline
# ---------------------------------------------------------
# Replaces determine_cve_applicability() from nvd_api.py.
#
# APPLICABILITY
# -------------
# NVD "configurations" are boolean trees:
#   configuration -> nodes -> (nodes ...) -> cpeMatch leaves
# each node has an operator (AND / OR) and an optional negate flag.
#
# This module evaluates the tree with THREE-VALUED logic
# (TRUE / FALSE / UNKNOWN), so anything we cannot establish stays
# UNKNOWN instead of being silently dropped or silently accepted.
#
#   AND: any FALSE -> FALSE, else any UNKNOWN -> UNKNOWN, else TRUE
#   OR : any TRUE  -> TRUE,  else any UNKNOWN -> UNKNOWN, else FALSE
#   negate: TRUE <-> FALSE, UNKNOWN stays UNKNOWN
#
# Leaves:
#   * target product (exact vendor + product): version / range test
#   * operating-system CPE ("running on" conditions): compared with the
#     recorded environment (os_family, os_cpes); FALSE only when the OS
#     family clearly differs, UNKNOWN when it cannot be decided
#   * any other application CPE: evaluated only if the environment
#     records that product and version, otherwise UNKNOWN
#   * hardware CPEs: UNKNOWN
#
# Final status per CVE:
#   AFFECTED      some configuration naming the target evaluates TRUE
#                 AND contains a "vulnerable" CPE entry for the target
#   NOT_AFFECTED  every configuration naming the target evaluates FALSE,
#                 or no configuration names the target at all
#   UNKNOWN       otherwise (incl. no CPE data, unparseable versions,
#                 unrecorded conditions)
#
# KNOWN LIMITATIONS (not implemented)
#   * Only the product and OS conditions above are evaluated; other
#     products are UNKNOWN unless listed in environment["products"].
#   * OS version ranges are not evaluated (we do not record OS versions).
#   * Versions are compared with PEP 440 rules (packaging). Pre-release
#     / "update" labels in a CPE (e.g. 2.0.0:rc1) give UNKNOWN when the
#     base version matches, because detected versions drop such labels.
#   * Escaped special characters inside CPE fields are not unescaped.
#   * CVEs that NVD has not analysed (no configurations) are UNKNOWN;
#     this module does not read affected-version text from descriptions.
# ---------------------------------------------------------

import re

from packaging.version import Version, InvalidVersion

AFFECTED = "AFFECTED"
NOT_AFFECTED = "NOT_AFFECTED"
UNKNOWN = "UNKNOWN"

_TRUE = "TRUE"
_FALSE = "FALSE"
_UNKNOWN = "UNKNOWN"

# Canonical identity plus display-name compatibility.
COMPONENTS = {
    "mosquitto": {
        "display_name": "Mosquitto",
        "cpe_vendor": "eclipse",
        "cpe_product": "mosquitto",
    },
    "influxdb": {
        "display_name": "InfluxDB",
        "cpe_vendor": "influxdata",
        "cpe_product": "influxdb",
    },
    "ditto": {
        "display_name": "Eclipse Ditto",
        "cpe_vendor": "eclipse",
        "cpe_product": "ditto",
    },
}

DISPLAY_NAME_TO_COMPONENT = {
    definition["display_name"]: component_id
    for component_id, definition in COMPONENTS.items()
}

# Backwards-compatible display-name lookup used by baseline.py and tests.
TARGETS = {
    definition["display_name"]: (
        definition["cpe_vendor"],
        definition["cpe_product"],
    )
    for definition in COMPONENTS.values()
}

# Facts about the deployment that CPE conditions are checked against.
# Default: the three services run in Linux containers. This is an
# assumption, recorded here until environment.json replaces it.
DEFAULT_ENVIRONMENT = {
    "os_family": "linux",
    "os_cpes": [("linux", "linux_kernel")],
    "products": {},          # {(vendor, product): "version"}
}

_CPE_SPLIT = re.compile(r"(?<!\\):")


def resolve_component_id(component):
    """Resolve canonical IDs and historical display names to a canonical ID."""

    if component in COMPONENTS:
        return component

    return DISPLAY_NAME_TO_COMPONENT.get(component)


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def _ver(text):
    try:
        return Version(text)
    except (InvalidVersion, TypeError):
        return None


def _parse_cpe(criteria):
    """cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:..."""
    parts = _CPE_SPLIT.split(criteria or "")
    if len(parts) < 7 or parts[0] != "cpe":
        return None
    return {
        "part": parts[2],
        "vendor": parts[3].lower(),
        "product": parts[4].lower(),
        "version": parts[5],
        "update": parts[6],
    }


def _version_test_decision(current_text, cpe, match):
    """Evaluate a CPE version test and retain the exact decision evidence."""

    constraints = {
        "start_including": match.get("versionStartIncluding"),
        "start_excluding": match.get("versionStartExcluding"),
        "end_including": match.get("versionEndIncluding"),
        "end_excluding": match.get("versionEndExcluding"),
    }
    current = _ver(current_text)

    if current is None:
        return {
            "status": _UNKNOWN,
            "reason": "Detected version could not be parsed.",
            "current_version": current_text,
            "cpe_version": cpe["version"],
            "cpe_update": cpe["update"],
            "constraints": constraints,
        }

    cpe_version = cpe["version"]
    bounds = (
        (match.get("versionStartIncluding"), lambda b: current >= b),
        (match.get("versionStartExcluding"), lambda b: current > b),
        (match.get("versionEndIncluding"), lambda b: current <= b),
        (match.get("versionEndExcluding"), lambda b: current < b),
    )
    has_range = any(bound for bound, _ in bounds)

    if cpe_version not in ("*", "-"):
        exact = _ver(cpe_version)

        if exact is None:
            return {
                "status": _UNKNOWN,
                "reason": "CPE exact version could not be parsed.",
                "current_version": current_text,
                "cpe_version": cpe_version,
                "cpe_update": cpe["update"],
                "constraints": constraints,
            }

        if current != exact:
            return {
                "status": _FALSE,
                "reason": "Detected version does not equal the exact CPE version.",
                "current_version": current_text,
                "cpe_version": cpe_version,
                "cpe_update": cpe["update"],
                "constraints": constraints,
            }

        if cpe["update"] not in ("*", "-"):
            return {
                "status": _UNKNOWN,
                "reason": (
                    "CPE update qualifier is not represented in the "
                    "detected version."
                ),
                "current_version": current_text,
                "cpe_version": cpe_version,
                "cpe_update": cpe["update"],
                "constraints": constraints,
            }

        return {
            "status": _TRUE,
            "reason": "Detected version equals the exact CPE version.",
            "current_version": current_text,
            "cpe_version": cpe_version,
            "cpe_update": cpe["update"],
            "constraints": constraints,
        }

    if not has_range:
        return {
            "status": _TRUE if cpe_version == "*" else _UNKNOWN,
            "reason": (
                "Wildcard CPE version accepts any version."
                if cpe_version == "*"
                else "CPE version is unavailable."
            ),
            "current_version": current_text,
            "cpe_version": cpe_version,
            "cpe_update": cpe["update"],
            "constraints": constraints,
        }

    unparsed = False

    for bound, test in bounds:
        if not bound:
            continue
        parsed = _ver(bound)

        if parsed is None:
            unparsed = True
        elif not test(parsed):
            return {
                "status": _FALSE,
                "reason": "Detected version falls outside a CPE range bound.",
                "current_version": current_text,
                "cpe_version": cpe_version,
                "cpe_update": cpe["update"],
                "constraints": constraints,
            }

    return {
        "status": _UNKNOWN if unparsed else _TRUE,
        "reason": (
            "One or more CPE range bounds could not be parsed."
            if unparsed
            else "Detected version satisfies all CPE range bounds."
        ),
        "current_version": current_text,
        "cpe_version": cpe_version,
        "cpe_update": cpe["update"],
        "constraints": constraints,
    }


def _version_test(current_text, cpe, match):
    """Is current_text inside what this CPE entry describes? T/F/U."""

    return _version_test_decision(current_text, cpe, match)["status"]


def _os_family(vendor, product):
    text = f"{vendor} {product}"
    if "windows" in text or "microsoft" in vendor:
        return "windows"
    if "mac_os" in text or "macos" in text or "apple" in vendor:
        return "macos"
    for word in ("linux", "debian", "ubuntu", "alpine", "redhat",
                 "centos", "fedora", "suse", "android"):
        if word in text:
            return "linux"
    return None


def _condition_leaf_decision(cpe, match, environment):
    """Decision evidence for a CPE that is not the target product."""

    if cpe["part"] == "o":
        env_family = environment.get("os_family")
        family = _os_family(cpe["vendor"], cpe["product"])
        recorded = (cpe["vendor"], cpe["product"]) in [
            tuple(item) for item in environment.get("os_cpes", [])
        ]
        no_version = (
            cpe["version"] in ("*", "-")
            and not any(match.get(k) for k in (
                "versionStartIncluding", "versionStartExcluding",
                "versionEndIncluding", "versionEndExcluding"))
        )

        if not env_family or not family:
            status = _UNKNOWN
            reason = "Operating-system condition could not be classified."
        elif family != env_family:
            status = _FALSE
            reason = "Required operating-system family differs from deployment."
        elif recorded and no_version:
            status = _TRUE
            reason = "Recorded operating-system CPE satisfies the condition."
        else:
            status = _UNKNOWN
            reason = "Operating-system version or distribution is not established."

        return {
            "status": status,
            "reason": reason,
            "platform_family": family,
            "environment_family": env_family,
            "recorded_os_cpe": recorded,
            "version_constrained": not no_version,
        }

    if cpe["part"] == "a":
        known_version = environment.get("products", {}).get(
            (cpe["vendor"], cpe["product"])
        )

        if known_version is None:
            return {
                "status": _UNKNOWN,
                "reason": "Presence of another required application is unknown.",
                "known_version": None,
            }

        decision = _version_test_decision(
            known_version,
            cpe,
            match
        )
        decision["reason"] = (
            "Additional application condition: " + decision["reason"]
        )
        return decision

    return {
        "status": _UNKNOWN,
        "reason": f"Unsupported CPE part: {cpe['part']}.",
    }


def _condition_leaf(cpe, match, environment):
    """Leaf for a CPE that is not the target product."""

    return _condition_leaf_decision(
        cpe,
        match,
        environment
    )["status"]


def _combine(operator, values):
    if operator == "AND":
        if _FALSE in values:
            return _FALSE
        if _UNKNOWN in values:
            return _UNKNOWN
        return _TRUE
    # OR (NVD default)
    if _TRUE in values:
        return _TRUE
    if _UNKNOWN in values:
        return _UNKNOWN
    return _FALSE


def _negate(value):
    if value == _TRUE:
        return _FALSE
    if value == _FALSE:
        return _TRUE
    return _UNKNOWN


def _leaf_decision(match, ctx):
    cpe = _parse_cpe(match.get("criteria"))

    if cpe is None:
        return {
            "kind": "cpe_match",
            "criteria": match.get("criteria"),
            "vulnerable": bool(match.get("vulnerable", False)),
            "target_product": False,
            "status": _UNKNOWN,
            "reason": "CPE criteria could not be parsed.",
        }

    is_target = (
        cpe["part"] == "a"
        and cpe["vendor"] == ctx["vendor"]
        and cpe["product"] == ctx["product"]
    )

    if is_target:
        ctx["saw_target"] = True

        if match.get("vulnerable", False):
            ctx["saw_vulnerable_target"] = True

        decision = _version_test_decision(
            ctx["version"],
            cpe,
            match
        )
    else:
        decision = _condition_leaf_decision(
            cpe,
            match,
            ctx["environment"]
        )

    return {
        "kind": "cpe_match",
        "criteria": match.get("criteria"),
        "vulnerable": bool(match.get("vulnerable", False)),
        "target_product": is_target,
        "parsed_cpe": cpe,
        **decision,
    }


def _leaf(match, ctx):
    return _leaf_decision(match, ctx)["status"]


def _eval_node_decision(node, ctx):
    """Evaluate a configuration node and retain its boolean evidence tree."""

    operator = str(node.get("operator", "OR")).upper()
    children = []
    values = []

    for match in node.get("cpeMatch", []):
        decision = _leaf_decision(match, ctx)
        children.append(decision)
        values.append(decision["status"])

    for child in node.get("nodes", []):
        decision = _eval_node_decision(child, ctx)
        children.append(decision)

        if decision["status"] is not None:
            values.append(decision["status"])

    raw_result = _combine(operator, values) if values else None
    negated = bool(node.get("negate"))
    result = _negate(raw_result) if negated and raw_result is not None else raw_result

    return {
        "kind": "node",
        "operator": operator,
        "negated": negated,
        "child_results": children,
        "raw_result": raw_result,
        "status": result,
    }


def _eval_node(node, ctx):
    """Evaluate a configuration / node. Returns T/F/U or None if empty."""

    return _eval_node_decision(node, ctx)["status"]


# ---------------------------------------------------------
# Public: applicability
# ---------------------------------------------------------

def _serialisable_environment(environment):
    """Return a JSON-friendly copy of the deployment environment evidence."""

    return {
        "os_family": environment.get("os_family"),
        "os_cpes": [
            list(item)
            for item in environment.get("os_cpes", [])
        ],
        "products": {
            f"{vendor}:{product}": product_version
            for (vendor, product), product_version
            in environment.get("products", {}).items()
        },
    }


def evaluate_applicability(cve_item, component, version, environment=None):
    """
    Evaluate a CVE and return status, reason and structured CPE provenance.

    ``component`` accepts either a canonical ID such as ``mosquitto`` or a
    historical display name such as ``Mosquitto``.
    """

    component_id = resolve_component_id(component)

    if component_id is None:
        reason = f"No CPE vendor/product configured for {component}."
        return {
            "cve_id": cve_item.get("cve", {}).get("id"),
            "status": UNKNOWN,
            "reason": reason,
            "component": {
                "requested": component,
                "canonical_id": None,
                "display_name": None,
                "cpe_vendor": None,
                "cpe_product": None,
            },
            "version": version,
            "environment": None,
            "environment_source": None,
            "configurations": [],
        }

    definition = COMPONENTS[component_id]
    vendor = definition["cpe_vendor"]
    product = definition["cpe_product"]
    environment_source = (
        "caller"
        if environment is not None
        else "DEFAULT_ENVIRONMENT"
    )
    environment = (
        DEFAULT_ENVIRONMENT
        if environment is None
        else environment
    )
    configurations = cve_item.get("cve", {}).get("configurations", [])
    provenance = {
        "cve_id": cve_item.get("cve", {}).get("id"),
        "component": {
            "requested": component,
            "canonical_id": component_id,
            "display_name": definition["display_name"],
            "cpe_vendor": vendor,
            "cpe_product": product,
        },
        "version": version,
        "environment": _serialisable_environment(environment),
        "environment_source": environment_source,
        "configurations": [],
    }

    if not configurations:
        provenance["status"] = UNKNOWN
        provenance["reason"] = (
            "NVD has no CPE configuration for this CVE "
            "(not analysed yet)."
        )
        return provenance

    values = []
    note = None

    for index, configuration in enumerate(configurations):
        ctx = {
            "vendor": vendor,
            "product": product,
            "version": version,
            "environment": environment,
            "saw_target": False,
            "saw_vulnerable_target": False,
        }
        decision = _eval_node_decision(
            configuration,
            ctx
        )
        value = decision["status"]
        guard_reason = None

        if ctx["saw_target"] and value == _TRUE and not ctx["saw_vulnerable_target"]:
            value = _UNKNOWN
            guard_reason = (
                f"{vendor}:{product} appears only as a platform condition; "
                "the vulnerable software is a different product."
            )
            note = guard_reason

        config_record = {
            "configuration_index": index,
            "named_target": ctx["saw_target"],
            "vulnerable_target_found": ctx["saw_vulnerable_target"],
            "result_before_product_guard": decision["status"],
            "result": value,
            "product_guard_reason": guard_reason,
            "decision_tree": decision,
        }
        provenance["configurations"].append(config_record)

        if ctx["saw_target"]:
            values.append(value)

    if not values:
        provenance["status"] = NOT_AFFECTED
        provenance["reason"] = (
            f"CPE data exists but does not name "
            f"{vendor}:{product}."
        )
    elif _TRUE in values:
        provenance["status"] = AFFECTED
        provenance["reason"] = (
            f"Version {version} satisfies an affected configuration "
            "(version range and platform conditions)."
        )
    elif _UNKNOWN in values:
        provenance["status"] = UNKNOWN
        provenance["reason"] = note or (
            "Applicability depends on a condition that could not be "
            "evaluated (version format, platform, or another product)."
        )
    else:
        provenance["status"] = NOT_AFFECTED
        provenance["reason"] = (
            f"Version {version} does not satisfy any configuration "
            f"naming {vendor}:{product}."
        )

    provenance["decision_counts"] = {
        "AFFECTED": values.count(_TRUE),
        "NOT_AFFECTED": values.count(_FALSE),
        "UNKNOWN": values.count(_UNKNOWN),
    }
    return provenance


def determine_applicability(cve_item, component, version, environment=None):
    """Compatibility wrapper returning ``(status, reason)``."""

    result = evaluate_applicability(
        cve_item,
        component,
        version,
        environment
    )
    return result["status"], result["reason"]


# ---------------------------------------------------------
# CVSS policy for the baseline
# ---------------------------------------------------------
# PRIMARY SCALE: CVSS v3.x (v3.1 and v3.0 are treated as one family;
# their base-score formulas are the same apart from minor rounding
# changes). It matches cvss_model.py.
#
# For each CVE:
#   primary  = one v3.x entry, chosen by:
#                1. NVD "Primary" analysis over "Secondary" (CNA) source
#                2. v3.1 over v3.0
#                3. first listed
#   other    = every remaining entry (v4.0, v2.0, extra v3.x entries),
#              retained and reported, NEVER merged into the ranking
#   all      = primary + other
#
# Ranking uses only primary scores. CVEs with no v3.x score are kept
# in a separate group and are not interleaved with ranked CVEs.
# ---------------------------------------------------------

PRIMARY_VERSIONS = ("3.1", "3.0")
PRIMARY_SCALE_LABEL = "CVSS v3.x"

_METRIC_KEYS = (
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV2", "2.0"),
)


def cvss_all(cve_item):
    """Every CVSS entry on the CVE, normalised, nothing discarded."""

    metrics = cve_item.get("cve", {}).get("metrics", {})
    entries = []

    for key, label in _METRIC_KEYS:
        for entry in metrics.get(key, []):
            data = entry.get("cvssData", {})
            entries.append({
                "version": label,
                "score": data.get("baseScore"),
                "severity": data.get("baseSeverity") or entry.get("baseSeverity"),
                "vector": data.get("vectorString"),
                "source_type": entry.get("type"),   # Primary / Secondary
                "source": entry.get("source"),
            })

    return entries


def _primary_rank(entry):
    # lower sorts first = preferred
    return (
        0 if entry["source_type"] == "Primary" else 1,
        PRIMARY_VERSIONS.index(entry["version"]),
    )


def cvss_summary(cve_item):
    """
    Apply the policy above.
    Returns {"scale": str, "primary": entry|None, "other": [entries],
             "all": [entries]}
    """

    entries = cvss_all(cve_item)

    candidates = [
        e for e in entries
        if e["version"] in PRIMARY_VERSIONS and e["score"] is not None
    ]

    primary = min(candidates, key=_primary_rank) if candidates else None
    other = [e for e in entries if e is not primary]

    return {
        "scale": PRIMARY_SCALE_LABEL,
        "primary": primary,
        "other": other,
        "all": entries,
    }
