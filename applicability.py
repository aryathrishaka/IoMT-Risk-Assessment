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

# component name -> (cpe vendor, cpe product)
TARGETS = {
    "Mosquitto": ("eclipse", "mosquitto"),
    "InfluxDB": ("influxdata", "influxdb"),
    "Eclipse Ditto": ("eclipse", "ditto"),
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


def _version_test(current_text, cpe, match):
    """Is current_text inside what this CPE entry describes? T/F/U."""

    current = _ver(current_text)
    if current is None:
        return _UNKNOWN

    cpe_version = cpe["version"]
    bounds = (
        (match.get("versionStartIncluding"), lambda b: current >= b),
        (match.get("versionStartExcluding"), lambda b: current > b),
        (match.get("versionEndIncluding"), lambda b: current <= b),
        (match.get("versionEndExcluding"), lambda b: current < b),
    )
    has_range = any(bound for bound, _ in bounds)

    # Exact version written in the CPE string
    if cpe_version not in ("*", "-"):
        exact = _ver(cpe_version)
        if exact is None:
            return _UNKNOWN
        if current != exact:
            return _FALSE
        if cpe["update"] not in ("*", "-"):
            return _UNKNOWN          # e.g. 2.0.0:rc1 vs detected 2.0.0
        return _TRUE

    # Wildcard, no range: every version
    if not has_range:
        return _TRUE if cpe_version == "*" else _UNKNOWN

    unparsed = False
    for bound, test in bounds:
        if not bound:
            continue
        parsed = _ver(bound)
        if parsed is None:
            unparsed = True
        elif not test(parsed):
            return _FALSE
    return _UNKNOWN if unparsed else _TRUE


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


def _condition_leaf(cpe, match, environment):
    """Leaf for a CPE that is not the target product."""

    if cpe["part"] == "o":
        env_family = environment.get("os_family")
        family = _os_family(cpe["vendor"], cpe["product"])
        if not env_family or not family:
            return _UNKNOWN
        if family != env_family:
            return _FALSE
        # Same family: only an exact recorded OS CPE without version
        # constraints counts as satisfied.
        no_version = (
            cpe["version"] in ("*", "-")
            and not any(match.get(k) for k in (
                "versionStartIncluding", "versionStartExcluding",
                "versionEndIncluding", "versionEndExcluding"))
        )
        recorded = (cpe["vendor"], cpe["product"]) in [
            tuple(item) for item in environment.get("os_cpes", [])
        ]
        return _TRUE if (recorded and no_version) else _UNKNOWN

    if cpe["part"] == "a":
        known_version = environment.get("products", {}).get(
            (cpe["vendor"], cpe["product"])
        )
        if known_version is None:
            return _UNKNOWN          # presence not established
        return _version_test(known_version, cpe, match)

    return _UNKNOWN


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


def _leaf(match, ctx):
    cpe = _parse_cpe(match.get("criteria"))
    if cpe is None:
        return _UNKNOWN

    is_target = (
        cpe["part"] == "a"
        and cpe["vendor"] == ctx["vendor"]
        and cpe["product"] == ctx["product"]
    )

    if is_target:
        ctx["saw_target"] = True
        if match.get("vulnerable", False):
            ctx["saw_vulnerable_target"] = True
        return _version_test(ctx["version"], cpe, match)

    return _condition_leaf(cpe, match, ctx["environment"])


def _eval_node(node, ctx):
    """Evaluate a configuration / node. Returns T/F/U or None if empty."""

    values = [_leaf(m, ctx) for m in node.get("cpeMatch", [])]

    for child in node.get("nodes", []):
        value = _eval_node(child, ctx)
        if value is not None:
            values.append(value)

    if not values:
        return None

    result = _combine(str(node.get("operator", "OR")).upper(), values)
    if node.get("negate"):
        result = _negate(result)
    return result


# ---------------------------------------------------------
# Public: applicability
# ---------------------------------------------------------

def determine_applicability(cve_item, component, version, environment=None):
    """
    Returns (status, reason).
    status is AFFECTED, NOT_AFFECTED or UNKNOWN.
    """

    if component not in TARGETS:
        return UNKNOWN, f"No CPE vendor/product configured for {component}."

    environment = DEFAULT_ENVIRONMENT if environment is None else environment
    vendor, product = TARGETS[component]

    configurations = cve_item.get("cve", {}).get("configurations", [])
    if not configurations:
        return UNKNOWN, "NVD has no CPE configuration for this CVE (not analysed yet)."

    values = []
    note = None

    for configuration in configurations:
        ctx = {
            "vendor": vendor,
            "product": product,
            "version": version,
            "environment": environment,
            "saw_target": False,
            "saw_vulnerable_target": False,
        }

        value = _eval_node(configuration, ctx)

        if not ctx["saw_target"]:
            continue

        if value == _TRUE and not ctx["saw_vulnerable_target"]:
            value = _UNKNOWN
            note = (f"{vendor}:{product} appears only as a platform condition; "
                    "the vulnerable software is a different product.")

        values.append(value)

    if not values:
        return NOT_AFFECTED, f"CPE data exists but does not name {vendor}:{product}."

    if _TRUE in values:
        return AFFECTED, (f"Version {version} satisfies an affected configuration "
                          "(version range and platform conditions).")

    if _UNKNOWN in values:
        return UNKNOWN, note or (
            "Applicability depends on a condition that could not be evaluated "
            "(version format, platform, or another product)."
        )

    return NOT_AFFECTED, (f"Version {version} does not satisfy any configuration "
                          f"naming {vendor}:{product}.")


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
