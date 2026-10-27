"""Small builders for NVD-shaped test records, plus a tiny test runner."""

import sys
import traceback


def cpe(product, vendor="eclipse", version="*", update="*", part="a",
        vulnerable=True, **range_keys):
    match = {
        "vulnerable": vulnerable,
        "criteria": f"cpe:2.3:{part}:{vendor}:{product}:{version}:{update}"
                    ":*:*:*:*:*:*",
    }
    match.update(range_keys)
    return match


def node(*matches, operator="OR", negate=False, nodes=None):
    d = {"operator": operator, "negate": negate, "cpeMatch": list(matches)}
    if nodes:
        d["nodes"] = list(nodes)
    return d


def config(*nodes, operator="OR", negate=False):
    return {"operator": operator, "negate": negate, "nodes": list(nodes)}


def metric_entry(score, entry_type="Primary", severity="HIGH", vector=None):
    return {
        "type": entry_type,
        "source": "test",
        "cvssData": {"baseScore": score, "baseSeverity": severity,
                     "vectorString": vector or "VECTOR"},
    }


def v2_entry(score, severity="HIGH"):
    # CVSS 2.0 keeps severity outside cvssData
    return {"type": "Primary", "source": "test", "baseSeverity": severity,
            "cvssData": {"baseScore": score, "vectorString": "AV:N/AC:L"}}


def cve(cve_id, configurations=None, metrics=None):
    record = {"cve": {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": f"{cve_id} description"}],
        "metrics": metrics or {},
    }}
    if configurations is not None:
        record["cve"]["configurations"] = configurations
    return record


def simple(cve_id, *matches, metrics=None):
    """One configuration, one OR node."""
    return cve(cve_id, [config(node(*matches))], metrics)


def run_all(namespace):
    tests = [(n, f) for n, f in namespace.items()
             if n.startswith("test_") and callable(f)]
    failed = 0
    for name, func in tests:
        try:
            func()
            print(f"PASS  {name}")
        except Exception:
            failed += 1
            print(f"FAIL  {name}")
            traceback.print_exc()
    print()
    print(f"{len(tests) - failed}/{len(tests)} passed")
    if failed:
        sys.exit(1)
