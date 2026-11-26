"""arch_ratchet: the duplicate count may only fall. Clusters are stored as fingerprints with their site counts in
`.arch/baseline.json` under "literals"; a new cluster, a new divergence or a new site fails; a removal lowers the baseline.
Exceptions live in `.arch/exceptions.toml` with a concept id, a reason and an expiry date."""

import datetime as dt
import json
from pathlib import Path

import arch_config as ac
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


def promote_bans(root, canon, failing, warns, base=None):
    """(failing, warns) with canon.* warnings in the files this change touched moved into failing (AC-02).

    Off when the canon says `ban_mode: warn`. A violation in a file this change did not touch stays a warning,
    so an old unbaselined one never fails an unrelated PR."""
    if canon.get("ban_mode") == "warn":
        return failing, warns
    added, mod = ac.changed_files(root, ac.base_ref(root, base))
    touched = set(added) | set(mod)
    moved = [
        v for v in warns if v["rule"].startswith("canon.") and v["path"] in touched
    ]
    ids = {id(v) for v in moved}
    return failing + moved, [v for v in warns if id(v) not in ids]


FORBIDDEN_RULES = (
    "canon.",
    "transition.",
)  # ownership and transition rules: fix them, never baseline them
CANNOT_BASELINE = "ownership and transition violations cannot be baselined: fix them"


def record_entry(baseline, key, owner, reason, expires):
    """Store who owns a baselined violation, why, and when it lapses (AC-04). Refuses ownership and transition rules."""
    if key.startswith(FORBIDDEN_RULES):
        raise ValueError(CANNOT_BASELINE)
    for name, value in (("owner", owner), ("reason", reason), ("expires", expires)):
        if not str(value or "").strip():
            raise ValueError(f"baseline entry for {key} needs a {name}")
    baseline.setdefault("entries", {})[key] = {
        "owner": owner,
        "reason": reason,
        "expires": str(expires),
    }
    return baseline


def baseline_problems(baseline, today):
    """{'unowned', 'expired', 'forbidden'}: sorted baseline keys with no complete entry, a past expiry, or a forbidden rule."""
    entries = baseline.get("entries") or {}
    keys = list(baseline.get("violations") or {})
    complete = {
        k
        for k, e in entries.items()
        if all(
            str((e or {}).get(f) or "").strip() for f in ("owner", "reason", "expires")
        )
    }
    return {
        "unowned": sorted(k for k in keys if k not in complete),
        "expired": sorted(
            k
            for k, e in entries.items()
            if k in keys and str((e or {}).get("expires") or "9999") < today.isoformat()
        ),
        "forbidden": sorted(k for k in keys if k.startswith(FORBIDDEN_RULES)),
    }


def expired_violations(problems):
    """One failing violation per expired baseline entry."""
    return [
        {
            "rule": "baseline.expired",
            "path": k,
            "target": "",
            "detail": f"baseline entry {k} expired; fix it or renew it",
            "key": f"baseline.expired|{k}|",
        }
        for k in problems["expired"]
    ]


def counts_block(n_new, outstanding, problems):
    return {
        "new": n_new,
        "outstanding": outstanding,
        "expired": len(problems["expired"]),
        "unowned": len(problems["unowned"]),
        "failing_guards": None,
    }


def counts_line(n):
    return (
        f"  counts: new {n['new']}, outstanding {n['outstanding']}, expired {n['expired']}, unowned {n['unowned']}, "
        "failing guards: not measured until the canaries exist"
    )
