"""arch_ratchet: the duplicate count may only fall. Clusters are stored as fingerprints with their site counts in
`.arch/baseline.json` under "literals"; a new cluster, a new divergence or a new site fails; a removal lowers the baseline.
Exceptions live in `.arch/exceptions.toml` with a concept id, a reason and an expiry date."""

import datetime as dt
import json
from pathlib import Path

import tomllib


def _baseline_path(root):
    return Path(root) / ".arch" / "baseline.json"


def ac_today():
    return dt.datetime.now().astimezone().date()


def load_baseline(root):
    p = _baseline_path(root)
    return json.loads(p.read_text()) if p.is_file() else {}


def snapshot(clusters):
    return {
        "clusters": {c["fingerprint"]: c["sites"] for c in clusters},
        "divergences": sorted(c["fingerprint"] for c in clusters if c["divergence"]),
    }


def load_exceptions(root):
    p = Path(root) / ".arch" / "exceptions.toml"
    if not p.is_file():
        return []
    return tomllib.loads(p.read_text()).get("exception", [])


def exception_problems(excs, today):
    """Exceptions that are incomplete or expired, as failure messages."""
    out = []
    for e in excs:
        cid = e.get("concept", "?")
        if not (e.get("concept") and e.get("reason") and e.get("expires")):
            out.append(
                f"exception {cid}: needs a concept id, a reason and an expiry date"
            )
        elif dt.date.fromisoformat(str(e["expires"])) < today:
            out.append(f"exception {cid}: expired on {e['expires']}")
    return out


def compare(clusters, baseline, excs=(), today=None):
    """Returns (failures, new_baseline_or_None). new_baseline is set when something was removed (lower it)."""
    today = today or ac_today()
    fails = exception_problems(excs, today)
    live = {
        e["concept"]
        for e in excs
        if e.get("concept")
        and e.get("reason")
        and e.get("expires")
        and dt.date.fromisoformat(str(e["expires"])) >= today
    }
    old = baseline.get("literals")
    if old is None:
        return (
            fails,
            None,
        )  # no baseline yet: the first run records one, nothing is judged new
    now = snapshot([c for c in clusters if c["id"] not in live])
    for c in clusters:
        if c["id"] in live:
            continue
        fp, was = c["fingerprint"], old["clusters"].get(c["fingerprint"])
        if was is None:
            fails.append(
                f"new duplicate {c['id']}: {c['sites']} sites, values {', '.join(c['values'])}"
            )
        elif c["sites"] > was:
            fails.append(f"duplicate {c['id']} grew from {was} to {c['sites']} sites")
        if c["divergence"] and fp not in old.get("divergences", []):
            fails.append(f"new divergence {c['id']}: values {', '.join(c['values'])}")
    lowered = {
        fp: min(n, now["clusters"][fp])
        for fp, n in old["clusters"].items()
        if fp in now["clusters"]
    }
    divs = [fp for fp in old.get("divergences", []) if fp in now["divergences"]]
    if not fails and (lowered != old["clusters"] or divs != old.get("divergences", [])):
        return fails, {"clusters": lowered, "divergences": divs}
    return fails, None


def write_baseline(root, literals):
    p = _baseline_path(root)
    data = load_baseline(root)
    data["literals"] = literals
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def run(root, clusters, today=None, write=True):
    """Compare, lower the baseline when something went away, record the first baseline when there is none."""
    root = Path(root)
    base = load_baseline(root)
    fails, lowered = compare(clusters, base, load_exceptions(root), today)
    if write and "literals" not in base:
        write_baseline(root, snapshot(clusters))
    elif write and lowered is not None:
        write_baseline(root, lowered)
    return fails
