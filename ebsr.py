"""Pure Evidence-Bounded Scenario Risk Profile evaluator.

This module implements the frozen EBSR mathematics without performing NVD,
Docker, CPE or filesystem operations. Callers supply evidence propositions,
path specifications and target-channel evidence.

Proposition values use:
    T - established
    F - contradicted
    U - unknown
    X - conflicting evidence

All returned structures are JSON-serialisable.
"""

from cvss_model import (
    CIA_VALUES,
    calculate_exploitability,
)


TRUE = "T"
FALSE = "F"
UNKNOWN = "U"
CONFLICT = "X"

ZERO = "ZERO"
QUANTIFIED = "QUANTIFIED"
UNCERTAIN = "UNCERTAIN"
UNQUANTIFIED = "UNQUANTIFIED"
PARTIALLY_QUANTIFIED = "PARTIALLY_QUANTIFIED"

CHANNELS = ("C", "I", "A")

_STATUS_ALIASES = {
    "T": TRUE,
    "TRUE": TRUE,
    "SUPPORTED": TRUE,
    "F": FALSE,
    "FALSE": FALSE,
    "NOT_SUPPORTED": FALSE,
    "U": UNKNOWN,
    "UNKNOWN": UNKNOWN,
    "X": CONFLICT,
    "CONFLICT": CONFLICT,
}

_MAX_METRICS = {
    "AV": "N",
    "AC": "L",
    "PR": "N",
    "UI": "N",
    "S": "U",
}

_EXPLOITABILITY_MAX = calculate_exploitability(_MAX_METRICS)

_CVSS_V31_REQUIRED_METRICS = {
    "AV", "AC", "PR", "UI", "S", "C", "I", "A"
}

_CVSS_V31_ALLOWED_VALUES = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "R"},
    "S": {"U", "C"},
    "C": {"N", "L", "H"},
    "I": {"N", "L", "H"},
    "A": {"N", "L", "H"},
}


def _validated_cvss_v31_metrics(vector):
    """Return valid CVSS v3.1 base metrics or None."""

    if not isinstance(vector, str):
        return None

    parts = vector.split("/")

    if not parts or parts[0] != "CVSS:3.1":
        return None

    metrics = {}

    for segment in parts[1:]:
        if ":" not in segment:
            return None

        key, value = segment.split(":", 1)

        if not key or not value or key in metrics:
            return None

        metrics[key] = value

    if not _CVSS_V31_REQUIRED_METRICS.issubset(metrics):
        return None

    for key, allowed in _CVSS_V31_ALLOWED_VALUES.items():
        if metrics[key] not in allowed:
            return None

    return metrics


def _normalise_status(value):
    """Convert a supported evidence status representation to T/F/U/X."""

    if isinstance(value, dict):
        value = value.get("status")

    if not isinstance(value, str):
        return UNKNOWN

    normalised = value.strip().upper()

    if normalised not in _STATUS_ALIASES:
        raise ValueError(f"Unsupported evidence status: {value}")

    return _STATUS_ALIASES[normalised]


def combine_evidence(values, operator="AND"):
    """
    Combine evidence states using the frozen EBSR precedence rules.

    For AND: FALSE dominates CONFLICT, which dominates UNKNOWN.
    For OR: TRUE dominates CONFLICT, which dominates UNKNOWN.
    """

    states = [_normalise_status(value) for value in values]
    operator = operator.upper()

    if operator == "AND":

        if FALSE in states:
            return FALSE

        if CONFLICT in states:
            return CONFLICT

        if UNKNOWN in states:
            return UNKNOWN

        return TRUE

    if operator == "OR":

        if TRUE in states:
            return TRUE

        if CONFLICT in states:
            return CONFLICT

        if UNKNOWN in states:
            return UNKNOWN

        return FALSE

    raise ValueError(f"Unsupported evidence operator: {operator}")


def evaluate_propositions(proposition_ids, propositions, operator="AND"):
    """
    Evaluate only the propositions referenced by proposition_ids.

    Missing proposition identifiers are treated as UNKNOWN. Consequently,
    a conflict in an unrelated proposition cannot affect this expression.
    """

    values = []

    for proposition_id in proposition_ids:

        if proposition_id not in propositions:
            values.append(UNKNOWN)

        else:
            values.append(
                _normalise_status(
                    propositions[proposition_id]
                )
            )

    return combine_evidence(values, operator)


def normalise_cvss_v31_exploitability(vector):
    """
    Return the frozen EBSR exploitability index for a CVSS v3.1 vector.

    None is returned when the vector is missing, invalid or not CVSS v3.1.
    The value is a comparative index, not an exploitation probability.
    """

    metrics = _validated_cvss_v31_metrics(vector)

    if metrics is None:
        return None

    try:
        exploitability = calculate_exploitability(metrics)
    except (KeyError, TypeError, ValueError):
        return None

    return exploitability / _EXPLOITABILITY_MAX


def calculate_source_impact(vector):
    """
    Return the source C/I/A values and frozen EBSR source impact index.

    This is the source-vulnerability calculation from the specification.
    It is not the official CVSS Impact sub-score.
    """

    metrics = _validated_cvss_v31_metrics(vector)

    if metrics is None:
        return None

    try:

        channels = {
            channel: CIA_VALUES[metrics[channel]]
            for channel in CHANNELS
        }

    except (KeyError, TypeError, ValueError):

        return None

    isc = 1.0

    for value in channels.values():
        isc *= 1.0 - value

    isc = 1.0 - isc
    isc_max = 1.0 - (1.0 - CIA_VALUES["H"]) ** 3

    return {
        "channels": channels,
        "impact_index": isc / isc_max
    }


def _normalise_interval(value):
    """Validate and return a JSON-friendly numeric interval."""

    if isinstance(value, (int, float)):
        interval = [float(value), float(value)]

    elif (
        isinstance(value, (list, tuple))
        and len(value) == 2
    ):
        interval = [float(value[0]), float(value[1])]

    else:
        raise ValueError("Magnitude must be a number or [lower, upper].")

    if not (
        0.0 <= interval[0]
        <= interval[1]
        <= 1.0
    ):
        raise ValueError("Magnitude interval must lie within [0, 1].")

    return interval


def _evaluate_channel(channel_spec, propositions):
    """Apply the frozen TRUE/FALSE/UNKNOWN/CONFLICT target rules."""

    if not isinstance(channel_spec, dict):
        return {
            "status": UNKNOWN,
            "interval": [0.0, 1.0],
            "proposition_id": None
        }

    proposition_id = channel_spec.get(
        "proposition_id"
    )

    if proposition_id is None:
        status = UNKNOWN
    else:
        status = evaluate_propositions(
            [proposition_id],
            propositions
        )

    if status == FALSE:

        return {
            "status": FALSE,
            "interval": [0.0, 0.0],
            "proposition_id": proposition_id
        }

    if status == CONFLICT:

        return {
            "status": CONFLICT,
            "interval": None,
            "proposition_id": proposition_id
        }

    if status == UNKNOWN:

        return {
            "status": UNKNOWN,
            "interval": [0.0, 1.0],
            "proposition_id": proposition_id
        }

    magnitude = channel_spec.get("magnitude")

    if magnitude is None:

        return {
            "status": UNQUANTIFIED,
            "interval": None,
            "proposition_id": proposition_id
        }

    try:
        interval = _normalise_interval(magnitude)
    except ValueError:

        return {
            "status": UNQUANTIFIED,
            "interval": None,
            "proposition_id": proposition_id
        }

    # A TRUE consequence must have a positive magnitude.
    if interval[0] <= 0.0:

        return {
            "status": UNQUANTIFIED,
            "interval": None,
            "proposition_id": proposition_id
        }

    return {
        "status": QUANTIFIED,
        "interval": interval,
        "proposition_id": proposition_id
    }


def evaluate_target_impact(target_channels, propositions):
    """Evaluate all target C/I/A channels."""

    if not isinstance(target_channels, dict):
        target_channels = {}

    return {
        channel: _evaluate_channel(
            target_channels.get(channel),
            propositions
        )
        for channel in CHANNELS
    }


def _collect_path_conditions(path):
    """Collect mandatory proposition IDs from all path steps."""

    proposition_ids = list(
        path.get("condition_ids", [])
    )

    for step in path.get("vulnerability_steps", []):
        proposition_ids.extend(
            step.get("condition_ids", [])
        )

    for step in path.get("action_steps", []):
        proposition_ids.extend(
            step.get("condition_ids", [])
        )

    # Repeated IDs represent the same proposition and need one evaluation.
    return list(dict.fromkeys(proposition_ids))


def _make_profile(
    path_result,
    scenario_id,
    attacker_id,
    target_component
):
    """Create a profile, retaining incomplete target-impact evidence."""

    feasibility = path_result["feasibility"]["interval"]
    impact = path_result["target_impact"]

    if feasibility is None:
        return None

    intervals = {}
    channel_statuses = {}

    for channel in CHANNELS:

        channel_result = impact[channel]
        interval = channel_result["interval"]

        intervals[channel] = (
            list(interval)
            if interval is not None
            else None
        )
        channel_statuses[channel] = channel_result["status"]

    incomplete_channels = [
        channel
        for channel in CHANNELS
        if intervals[channel] is None
    ]

    profile = {
        "scenario_id": scenario_id,
        "path_id": path_result["path_id"],
        "attacker_id": attacker_id,
        "target_component": target_component,
        "vulnerability_ids": list(
            path_result["vulnerability_ids"]
        ),
        "feasibility_interval": list(feasibility),
        "impact_intervals": intervals,
        "target_impact_status": channel_statuses,
        "incomplete_impact_channels": incomplete_channels,
        "quantification_scope": path_result[
            "feasibility"
        ]["quantification_scope"]
    }
    profile["pareto_eligible"] = _numeric_profile(profile)

    return profile


def evaluate_path(path, propositions):
    """
    Evaluate one path.

    Path schema:
        path_id
        condition_ids
        vulnerability_steps:
            cve_id, component, cvss_vector, condition_ids,
            reproduction_grade
        action_steps:
            step_id, mechanism, condition_ids
        target_channels:
            C/I/A: {proposition_id, magnitude}
    """

    if not isinstance(path, dict):
        raise ValueError("Path specification must be a dictionary.")

    path_id = path.get("path_id")
    vulnerability_steps = path.get(
        "vulnerability_steps",
        []
    )
    action_steps = path.get(
        "action_steps",
        []
    )

    gate_status = evaluate_propositions(
        _collect_path_conditions(path),
        propositions
    )

    vulnerability_ids = [
        step.get("cve_id")
        for step in vulnerability_steps
        if step.get("cve_id")
    ]

    exploitation_indices = []
    missing_cvss = False

    for step in vulnerability_steps:

        index = normalise_cvss_v31_exploitability(
            step.get("cvss_vector")
        )

        if index is None:
            missing_cvss = True
        else:
            exploitation_indices.append(index)

    no_vulnerability_steps = not vulnerability_steps
    has_non_cve_steps = bool(action_steps)
    technical_index = (
        min(exploitation_indices)
        if exploitation_indices and not missing_cvss
        else None
    )

    quantification_scope = (
        "CONDITIONAL_TECHNICAL_EXPLOITABILITY"
        if has_non_cve_steps
        else "CVSS_VULNERABILITY_STEPS"
    )

    if gate_status == FALSE:

        feasibility_status = ZERO
        interval = [0.0, 0.0]
        technical_value = technical_index

    elif gate_status == CONFLICT:

        feasibility_status = CONFLICT
        interval = None
        technical_value = technical_index

    elif no_vulnerability_steps or missing_cvss:

        feasibility_status = UNQUANTIFIED
        interval = None
        technical_value = technical_index

    elif gate_status == TRUE:

        feasibility_status = QUANTIFIED
        interval = [
            technical_index,
            technical_index
        ]
        technical_value = technical_index

    else:

        feasibility_status = UNCERTAIN
        interval = [0.0, technical_index]
        technical_value = technical_index

    target_impact = evaluate_target_impact(
        path.get("target_channels", {}),
        propositions
    )

    reproduction_grades = {
        step.get("cve_id"): step.get(
            "reproduction_grade",
            "NOT_TESTED"
        )
        for step in vulnerability_steps
        if step.get("cve_id")
    }

    return {
        "path_id": path_id,
        "gate_status": gate_status,
        "vulnerability_ids": vulnerability_ids,
        "reproduction_grades": reproduction_grades,
        "feasibility": {
            "status": feasibility_status,
            "interval": list(interval) if interval else None,
            "conditional_technical_exploitability": technical_value,
            "quantification_scope": quantification_scope,
            "complete_path_feasibility_quantified": (
                interval is not None
                and not has_non_cve_steps
            )
        },
        "target_impact": target_impact
    }


def _max_interval(intervals):
    """Return the componentwise maximum of numeric intervals."""

    return [
        max(interval[0] for interval in intervals),
        max(interval[1] for interval in intervals)
    ]


def evaluate_scenario(scenario, propositions):
    """
    Evaluate one target-specific scenario for one attacker.

    The scenario retains every path and computes a Pareto set over paths
    whose feasibility and C/I/A dimensions are numeric.
    """

    if not isinstance(scenario, dict):
        raise ValueError("Scenario specification must be a dictionary.")

    scenario_id = scenario.get("scenario_id")
    attacker_id = scenario.get("attacker_id")
    target_component = scenario.get(
        "target_component"
    )

    if not scenario_id:
        raise ValueError("Scenario requires scenario_id.")

    if not attacker_id:
        raise ValueError("Scenario requires attacker_id.")

    if not target_component:
        raise ValueError(
            "Scenario requires target_component."
        )

    paths = scenario.get("paths", [])

    if not paths:
        raise ValueError("Scenario requires at least one path.")

    path_results = []
    profiles = []
    unquantified_paths = []
    conflict_paths = []
    unquantified_target_impact_paths = []
    conflict_target_impact_paths = []
    incomplete_profiles = []
    numeric_feasibility_intervals = []

    for path in paths:

        result = evaluate_path(path, propositions)
        path_results.append(result)

        feasibility_status = result["feasibility"]["status"]

        if feasibility_status == UNQUANTIFIED:
            unquantified_paths.append(result["path_id"])

        if feasibility_status == CONFLICT:
            conflict_paths.append(result["path_id"])

        feasibility_interval = result["feasibility"]["interval"]

        if feasibility_interval is not None:
            numeric_feasibility_intervals.append(
                feasibility_interval
            )

        channel_states = result["target_impact"]
        unquantified_channels = [
            channel
            for channel in CHANNELS
            if channel_states[channel]["status"] == UNQUANTIFIED
        ]
        conflict_channels = [
            channel
            for channel in CHANNELS
            if channel_states[channel]["status"] == CONFLICT
        ]

        if (
            feasibility_status != ZERO
            and unquantified_channels
        ):
            unquantified_target_impact_paths.append({
                "path_id": result["path_id"],
                "channels": unquantified_channels
            })

        if (
            feasibility_status != ZERO
            and conflict_channels
        ):
            conflict_target_impact_paths.append({
                "path_id": result["path_id"],
                "channels": conflict_channels
            })

        if feasibility_status != ZERO:

            profile = _make_profile(
                result,
                scenario_id,
                attacker_id,
                target_component
            )

            if profile is not None:
                profiles.append(profile)

                if not profile["pareto_eligible"]:
                    incomplete_profiles.append(profile)

    pareto_profiles = pareto_max(profiles)

    feasibility_envelope = (
        _max_interval(numeric_feasibility_intervals)
        if numeric_feasibility_intervals
        else None
    )

    has_positive_feasibility = any(
        interval[1] > 0.0
        for interval in numeric_feasibility_intervals
    )
    incomplete = (
        bool(unquantified_paths)
        or bool(conflict_paths)
        or bool(unquantified_target_impact_paths)
        or bool(conflict_target_impact_paths)
        or any(
            result["feasibility"]["status"] != ZERO
            and not result["feasibility"][
                "complete_path_feasibility_quantified"
            ]
            for result in path_results
        )
    )

    if has_positive_feasibility:

        scenario_status = (
            PARTIALLY_QUANTIFIED
            if incomplete
            else QUANTIFIED
        )

    elif numeric_feasibility_intervals:

        scenario_status = (
            PARTIALLY_QUANTIFIED
            if incomplete
            else ZERO
        )

    elif unquantified_paths:

        scenario_status = UNQUANTIFIED

    elif conflict_paths:

        scenario_status = CONFLICT

    else:

        scenario_status = ZERO

    all_vulnerabilities = sorted({
        vulnerability_id
        for result in path_results
        for vulnerability_id in result["vulnerability_ids"]
    })

    return {
        "scenario_id": scenario_id,
        "attacker_id": attacker_id,
        "target_component": target_component,
        "status": scenario_status,
        "feasibility_envelope": feasibility_envelope,
        "pareto_profiles": pareto_profiles,
        "paths": path_results,
        "unquantified_paths": unquantified_paths,
        "conflict_paths": conflict_paths,
        "unquantified_target_impact_paths": (
            unquantified_target_impact_paths
        ),
        "conflict_target_impact_paths": (
            conflict_target_impact_paths
        ),
        "incomplete_profiles": incomplete_profiles,
        "vulnerability_ids": all_vulnerabilities
    }


def _numeric_profile(profile):
    """Return True when a profile has all required numeric intervals."""

    if not isinstance(profile, dict):
        return False

    if (
        not isinstance(profile.get("feasibility_interval"), list)
        or len(profile["feasibility_interval"]) != 2
    ):
        return False

    impacts = profile.get("impact_intervals")

    if not isinstance(impacts, dict):
        return False

    for channel in CHANNELS:

        interval = impacts.get(channel)

        if not isinstance(interval, list) or len(interval) != 2:
            return False

    return True


def pareto_dominates(profile_a, profile_b):
    """
    Return True when profile_a dominates profile_b.

    Both lower and upper bounds are compared for feasibility and all C/I/A
    channels. Non-numeric or status-bearing profiles are never dominated.
    """

    if not (
        _numeric_profile(profile_a)
        and _numeric_profile(profile_b)
    ):
        return False

    dimensions_a = [
        profile_a["feasibility_interval"],
        profile_a["impact_intervals"]["C"],
        profile_a["impact_intervals"]["I"],
        profile_a["impact_intervals"]["A"]
    ]
    dimensions_b = [
        profile_b["feasibility_interval"],
        profile_b["impact_intervals"]["C"],
        profile_b["impact_intervals"]["I"],
        profile_b["impact_intervals"]["A"]
    ]

    at_least_one_strict = False

    for interval_a, interval_b in zip(
        dimensions_a,
        dimensions_b
    ):

        if interval_a[0] < interval_b[0] or interval_a[1] < interval_b[1]:
            return False

        if interval_a[0] > interval_b[0] or interval_a[1] > interval_b[1]:
            at_least_one_strict = True

    return at_least_one_strict


def pareto_max(profiles):
    """Return the order-preserving Pareto-maximal subset."""

    profiles = list(profiles)
    result = []

    for index, profile in enumerate(profiles):

        if not _numeric_profile(profile):
            result.append(profile)
            continue

        dominated = False

        for other_index, other in enumerate(profiles):

            if index == other_index:
                continue

            if pareto_dominates(other, profile):
                dominated = True
                break

        if not dominated:
            result.append(profile)

    return result


def aggregate_component(
    scenario_results,
    target_component,
    attacker_id
):
    """
    Aggregate all scenarios for one component and one attacker profile.

    Uses Pareto profiles and a componentwise maximum feasibility envelope.
    No additive or noisy-OR aggregation is applied.
    """

    selected = [
        scenario
        for scenario in scenario_results
        if (
            scenario["target_component"] == target_component
            and scenario["attacker_id"] == attacker_id
        )
    ]

    profiles = [
        profile
        for scenario in selected
        for profile in scenario["pareto_profiles"]
    ]
    pareto_profiles = pareto_max(profiles)
    numeric_feasibility_intervals = []

    for scenario in selected:

        if "paths" in scenario:

            numeric_feasibility_intervals.extend([
                path_result["feasibility"]["interval"]
                for path_result in scenario["paths"]
                if path_result["feasibility"]["interval"] is not None
            ])

        else:

            numeric_feasibility_intervals.extend([
                profile["feasibility_interval"]
                for profile in scenario["pareto_profiles"]
                if _numeric_profile(profile)
            ])

    if not selected:

        status = UNQUANTIFIED

    elif any(
        interval[1] > 0.0
        for interval in numeric_feasibility_intervals
    ):

        status = (
            PARTIALLY_QUANTIFIED
            if any(
                scenario["status"] != QUANTIFIED
                for scenario in selected
            )
            else QUANTIFIED
        )

    elif any(
        scenario["status"] == PARTIALLY_QUANTIFIED
        for scenario in selected
    ):

        status = PARTIALLY_QUANTIFIED

    elif (
        numeric_feasibility_intervals
        and all(
        scenario["status"] == ZERO
        for scenario in selected
        )
    ):

        status = ZERO

    elif any(
        scenario["status"] == CONFLICT
        for scenario in selected
    ):

        status = CONFLICT

    else:

        status = UNQUANTIFIED

    return {
        "target_component": target_component,
        "attacker_id": attacker_id,
        "scenario_ids": [
            scenario["scenario_id"]
            for scenario in selected
        ],
        "vulnerability_ids": sorted({
            vulnerability_id
            for scenario in selected
            for vulnerability_id in scenario["vulnerability_ids"]
        }),
        "pareto_profiles": pareto_profiles,
        "feasibility_envelope": (
            _max_interval(numeric_feasibility_intervals)
            if numeric_feasibility_intervals
            else None
        ),
        "unquantified_paths": [
            {
                "scenario_id": scenario["scenario_id"],
                "path_ids": scenario["unquantified_paths"]
            }
            for scenario in selected
            if scenario["unquantified_paths"]
        ],
        "conflict_paths": [
            {
                "scenario_id": scenario["scenario_id"],
                "path_ids": scenario["conflict_paths"]
            }
            for scenario in selected
            if scenario["conflict_paths"]
        ],
        "unquantified_target_impact_paths": [
            {
                "scenario_id": scenario["scenario_id"],
                "paths": scenario.get(
                    "unquantified_target_impact_paths",
                    []
                )
            }
            for scenario in selected
            if scenario.get("unquantified_target_impact_paths")
        ],
        "conflict_target_impact_paths": [
            {
                "scenario_id": scenario["scenario_id"],
                "paths": scenario.get(
                    "conflict_target_impact_paths",
                    []
                )
            }
            for scenario in selected
            if scenario.get("conflict_target_impact_paths")
        ],
        "incomplete_profiles": [
            profile
            for scenario in selected
            for profile in scenario.get("incomplete_profiles", [])
        ],
        "status": status
    }


def aggregate_system(scenario_results, components):
    """
    Aggregate scenarios into independent component/attacker profiles.

    No system-wide additive score is produced.
    """

    attackers = sorted({
        scenario["attacker_id"]
        for scenario in scenario_results
    })

    by_component = {}

    for component in components:

        by_component[component] = {
            attacker_id: aggregate_component(
                scenario_results,
                component,
                attacker_id
            )
            for attacker_id in attackers
            if any(
                scenario["target_component"] == component
                and scenario["attacker_id"] == attacker_id
                for scenario in scenario_results
            )
        }

    return {
        "components": by_component
    }
