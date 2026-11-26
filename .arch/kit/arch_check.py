"""arch_check: the architecture check (SPEC-CHIEF-ARCHITECT section 5.3).

Compares today's violations with the set-based baseline (a multiset: key -> count), applies founder-approved scoped and
expiring exceptions, and splits what is left into failures (rules the founder chose to enforce) and warnings.
Legacy rules compare file sizes with the recorded sizes: a legacy file may not grow and no new file may appear.
"""

import datetime as dt
import os
import re
from collections import defaultdict
from pathlib import Path

import arch_config as ac
import arch_scan as sc

AUTO_PLACE = [
    "docs/**",
    "tests/**",
    "**/__tests__/**",
    "**/*.test.*",
    "**/*.spec.*",
    ".arch/**",
    ".lifecycle/**",
    ".aider.conf.yml",
    ".github/workflows/arch.yml",
    "e2e/**",
    "**/*.md",
    "supabase/migrations/**",
]
CLAMP = 5


def line_count(root, rel):
    try:
        return (Path(root) / rel).read_text(errors="replace").count("\n") + 1
    except OSError:
        return 0


def legacy_violations(root, files, canon, baseline):
    legacy = (canon.get("layers") or {}).get("legacy", [])
    sizes = baseline.get("legacy_files", {})
    out = []
    for f in files:
        if not (legacy and ac.matches(f, legacy)) or not f.endswith(ac.SOURCE_EXTS):
            continue
        lines, base = line_count(root, f), sizes.get(f)
        if base is None:
            out.append(
                sc.violation(
                    "legacy.new-file",
                    f,
                    "",
                    f"{f}: new file in a legacy area; put new code in the new layer",
                )
            )
        elif lines > base:
            out.append(
                sc.violation(
                    "legacy.growth",
                    f,
                    "",
                    f"{f}: legacy file grew from {base} to {lines} lines; it may not grow",
                )
            )
    return out


def current_violations(root, canon, baseline=None):
    """All violations from the rule scanners (legacy size rules need the baseline)."""
    files = ac.list_files(root, canon.get("ignore", []))
    src = ac.source_files(root, canon)
    edge_list = sc.edges(root, src, canon)
    out = (
        sc.layer_violations(edge_list, canon)
        + sc.ban_violations(root, src, canon)
        + sc.clones(root, src, canon)
        + sc.loose_violations(files, canon)
    )
    return out, files, edge_list


def counts(viols):
    c = defaultdict(int)
    for v in viols:
        c[v["key"]] += 1
    return c


def beyond_baseline(viols, baseline):
    """Violations beyond the recorded multiset: for each key keep only occurrences above the baseline count."""
    base = baseline.get("violations", {})
    if isinstance(base, list):
        base = {k: 1 for k in base}
    seen = defaultdict(int)
    out = []
    for v in viols:
        seen[v["key"]] += 1
        if seen[v["key"]] > base.get(v["key"], 0):
            out.append(v)
    return out


def apply_exceptions(viols, exceptions, today):
    """(remaining, covered, notes). Expired exceptions warn for GRACE_DAYS, then stop covering and fail."""
    remaining, covered, notes, dead = [], [], [], []
    for v in viols:
        hit = None
        for e in exceptions:
            if not (
                e.get("rule") == v["rule"]
                or v["rule"].startswith(str(e.get("rule")) + ".")
            ):
                continue
            scope = e.get("scope") or []
            scope = [scope] if isinstance(scope, str) else scope
            if scope and not (
                ac.matches(v["path"], scope) or ac.matches(v.get("target") or "", scope)
            ):
                continue
            try:
                exp = dt.date.fromisoformat(str(e.get("expires")))
            except ValueError:
                continue
            late = (today - exp).days
            if late <= 0:
                hit = e
                break
            if late <= ac.GRACE_DAYS:
                hit = e
                notes.append(
                    f"exception {e.get('decision_id')} expired {late} day(s) ago; it stops covering in {ac.GRACE_DAYS - late} day(s)"
                )
                break
            dead.append(e)
        (covered if hit else remaining).append(v)
    for e in {id(x): x for x in dead}.values():
        remaining.append(
            sc.violation(
                "exception.expired",
                e.get("scope")
                if isinstance(e.get("scope"), str)
                else str(e.get("scope")),
                str(e.get("decision_id")),
                f"exception {e.get('decision_id')} expired on {e.get('expires')}; renew or fix the code",
            )
        )
    return remaining, covered, sorted(set(notes))


def enforced(rule, enforce):
    return any(rule == e or rule.startswith(e + ".") for e in enforce)


SPEC_NAME_RE = re.compile(r"\bSPEC-[A-Z0-9][A-Z0-9-]*[A-Z0-9]\b")


def parse_touches(text):
    """Globs from the spec's `Touches: a, b/*` lines; a bare folder `a/b/` or `a/b` also allows everything under it."""
    out = []
    for ln in text.splitlines():
        m = re.match(r"\s*Touches:\s*(.+?)\s*$", ln)
        if not m:
            continue
        for x in m.group(1).split(","):
            x = re.sub(r"\s*\([^)]*\)\s*$", "", x.strip()).strip("`")  # "path (new)"
            if not x:
                continue
            out.append(x)
            if not any(c in x for c in "*?[") and "." not in x.rsplit("/", 1)[-1]:
                out.append(x.rstrip("/") + "/**")
    return out


def spec_touches(root, base):
    """(spec name, allowed globs) from the Touches: line of the spec named in this branch's commit messages.

    Each spec carries its own place list, so two PRs for two specs never edit one shared file (SPEC-SCALE-TO-50 SC-01).
    Fail closed: if the commits name more than one spec that has a Touches: line, or none, return (None, []) and the caller
    falls back to .arch/plan.json. The Touches: line is read from the base branch when the spec already exists there, so a PR
    cannot widen its own place list by editing it (a spec amendment is the founder's); a brand-new spec is read from HEAD.
    """
    log = ac.git(root, "log", "--format=%B", f"{base}..HEAD")
    found = {}
    for name in dict.fromkeys(SPEC_NAME_RE.findall(log)):
        rel = f"docs/specs/{name}.md"
        text = ac.git(root, "show", f"{base}:{rel}")
        if not text:
            try:
                p = Path(root) / rel
                text = (
                    p.read_text()
                    if p.is_file()
                    else ac.git(root, "show", f"HEAD:{rel}")
                )
            except OSError:
                text = ""
        touches = parse_touches(text) if text else []
        if touches:
            found[name] = touches
    if len(found) != 1:
        return None, []
    name = next(iter(found))
    return name, found[name]


def check_places(root, canon, base=None):
    """New files must sit inside the architecture plan's place list (or carry an exception)."""
    added, _ = ac.changed_files(root, ac.base_ref(root, base))
    auto = canon.get("place_auto", AUTO_PLACE)
    new = [
        f
        for f in added
        if not ac.matches(f, ac.DEFAULT_IGNORE) and not ac.matches(f, auto)
    ]
    if not new:
        return []
    spec, touches = spec_touches(root, ac.base_ref(root, base))
    if touches:
        return [
            sc.violation(
                "place",
                f,
                "",
                f"{f}: new file outside the Touches: line of {spec} {touches}",
            )
            for f in new
            if not ac.matches(f, touches)
        ]
    plan = ac.load_json(ac.arch_path(root, "plan.json"))
    if not plan or not plan.get("place"):
        return [
            sc.violation(
                "place",
                f,
                "",
                f"{f}: new file but there is no spec Touches: line and no architecture plan (.arch/plan.json with a place list)",
            )
            for f in new
        ]
    return [
        sc.violation(
            "place",
            f,
            "",
            f"{f}: new file outside the plan's place list {plan['place']}",
        )
        for f in new
        if not ac.matches(f, plan["place"])
    ]


def check_policy(root, base=None):
    """Changes to the policy files must be backed by a resolved decision recorded in .arch/decisions.log."""
    b = ac.base_ref(root, base)
    changed = []
    for name in ("canon.yaml", "exceptions.yaml", "baseline.json"):
        now = (
            ac.arch_path(root, name).read_text()
            if ac.arch_path(root, name).is_file()
            else ""
        )
        was = ac.git(root, "show", f"{b}:{ac.ARCH_DIR}/{name}")
        if now != was and (was or now):
            changed.append(name)
    if not changed:
        return []
    old_log = ac.git(root, "show", f"{b}:{ac.ARCH_DIR}/decisions.log").splitlines()
    new_refs = [r for r in ac.decision_refs_logged(root)][
        len([ln for ln in old_log if ln.strip()]) :
    ]
    # CI runners have no decisions folder: there a well-formed new log line stands in, and the PR review is the gate
    in_ci = bool(os.environ.get("CI"))
    valid = [
        r
        for r in new_refs
        if ac.resolve_decision_ref(r) or (in_ci and re.fullmatch(r"[\w.\-]+#\w+", r))
    ]
    if valid:
        return []
    return [
        sc.violation(
            "policy",
            f".arch/{n}",
            "",
            f".arch/{n} changed without a resolved decision recorded in .arch/decisions.log",
        )
        for n in changed
    ]


def literal_violations(root, today):
    """The duplicate ratchet; on only once `.arch/baseline.json` holds a "literals" section (written by --write-baseline)."""
    import arch_literals
    import arch_ratchet

    if "literals" not in arch_ratchet.load_baseline(root):
        return []
    clusters = arch_literals.cluster(arch_literals.extract(root))
    fails = arch_ratchet.run(root, clusters, today)
    return [sc.violation("dup.literal", ".arch/baseline.json", "", f) for f in fails]


def run_check(
    root, touched=False, base=None, places=False, policy=False, strict=False, today=None
):
    root = Path(root)
    canon = ac.load_canon(root)
    if canon is None:
        return {
            "ok": True,
            "failing": [],
            "warnings": [],
            "notes": ["no .arch/canon.yaml: nothing to check"],
            "baselined": 0,
            "covered": 0,
        }
    today = today or ac.today()
    baseline = ac.load_baseline(root)
    viols, files, _ = current_violations(root, canon, baseline)
    new = beyond_baseline(viols, baseline) + legacy_violations(
        root, files, canon, baseline
    )
    import arch_ratchet

    problems = arch_ratchet.baseline_problems(baseline, today)
    n_new = len(new)
    new += arch_ratchet.expired_violations(problems)
    if touched:
        added, mod = ac.changed_files(root, ac.base_ref(root, base))
        t = set(added) | set(mod)
        new = [v for v in new if v["path"] in t or (v.get("target") in t)]
    import arch_exceptions as ax
    import arch_gen

    new += ax.pending_violations(root)
    import arch_blind

    new += arch_blind.check_register(root, canon)
    if arch_gen.is_stale(root, canon):
        new.append(
            sc.violation(
                "gen.stale",
                "docs/ARCHITECTURE.md",
                "",
                "generated architecture files are stale; run arch-kit gen",
            )
        )
    if places:
        new += check_places(root, canon, base)
    if policy:
        new += check_policy(root, base)
    new += literal_violations(root, today)
    remaining, covered, notes = apply_exceptions(new, ac.load_exceptions(root), today)
    enforce = (
        set(canon["enforce"])
        | {"register", "dup.literal", "baseline.expired"}
        | ({"canon", "dup", "loose", "layer", "legacy"} if strict else set())
    )
    failing = [v for v in remaining if enforced(v["rule"], enforce)]
    warns = [v for v in remaining if v not in failing]
    import arch_jobs

    failing, warns = __import__("arch_ratchet").promote_bans(
        root, canon, failing, warns, base
    )
    return {
        "ok": not failing,
        "coverage": arch_jobs.coverage(root),
        "registered": sorted((canon.get("capabilities") or {}).keys()),
        "failing": failing,
        "warnings": warns,
        "notes": notes,
        "baselined": sum(counts(viols).values())
        - len(beyond_baseline(viols, baseline)),
        "covered": len(covered),
        "counts": arch_ratchet.counts_block(
            n_new, len(viols) - len(beyond_baseline(viols, baseline)), problems
        ),
    }


def format_result(res, limit=15):
    lines = [
        (
            f"architecture check: {'PASS' if res['ok'] else 'FAIL'} ({len(res['failing'])} failing, {len(res['warnings'])} warning(s), "
            f"{res['baselined']} known and baselined, {res['covered']} covered by exceptions)"
        )
    ]
    for tag, items in (("FAIL", res["failing"]), ("warn", res["warnings"])):
        lines += [f"  {tag} {v['rule']}: {v['detail']}" for v in items[:limit]]
        if len(items) > limit:
            lines.append(f"  ... and {len(items) - limit} more {tag}")
    lines += [f"  note: {n}" for n in res.get("notes", [])]
    if res.get("counts"):
        lines.append(__import__("arch_ratchet").counts_line(res["counts"]))
    if res.get("coverage"):
        import arch_jobs

        if res.get("registered"):
            lines.append("  registered jobs: " + ", ".join(res["registered"]))
        lines.append("  " + arch_jobs.coverage_line(res["coverage"]))
    return "\n".join(lines)


COVERAGE_REPOS = [
    "avbos-systems",
    "antimus",
    "aphra-lite-api",
    "aphra-lite-mobile",
    "AvB-Forecasting-BE",
    "avb-dashboard",
]
LOCAL_PATHS = {
    "avbos-systems": ".",
    "antimus": "~/projects/antimus",
    "AvB-Forecasting-BE": "~/projects/AvB-Forecasting-BE",
    "avb-dashboard": "~/projects/avb-dashboard",
}


def repo_path(name, here):
    """A local checkout when there is one, else a shallow read-only clone kept in a cache folder."""
    import subprocess

    if name == "avbos-systems":
        return Path(here)
    p = Path(LOCAL_PATHS.get(name, "")).expanduser() if name in LOCAL_PATHS else None
    if p and (p / ".git").exists():
        return p
    cache = (
        Path(
            os.environ.get(
                "ARCH_COVERAGE_CACHE", Path.home() / ".cache" / "arch-coverage"
            )
        )
        / name
    )
    if not (cache / ".git").exists():
        cache.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "gh",
                "repo",
                "clone",
                f"Ant-vs-Bear/{name}",
                str(cache),
                "--",
                "--depth",
                "1",
                "-q",
            ],
            check=True,
            capture_output=True,
        )
    return cache


def coverage_all(here=".", out=print):
    import arch_jobs

    rows = []
    for name in COVERAGE_REPOS:
        cov = arch_jobs.coverage(repo_path(name, here))
        cov["repo"] = name
        rows.append(cov)
        out(arch_jobs.coverage_line(cov))
    return rows


def main(argv=None):
    import argparse

    ap = argparse.ArgumentParser(prog="arch_check")
    ap.add_argument("--coverage-all", action="store_true")
    ap.add_argument(
        "--extract",
        action="store_true",
        help="find duplicates without being told what to look for",
    )
    ap.add_argument(
        "--rollout",
        choices=["status", "apply", "refresh"],
        help="list or open held PRs for repositories lacking the check",
    )
    ap.add_argument(
        "--nightly",
        action="store_true",
        help="write the org-wide list and a still-alive ping",
    )
    a = ap.parse_args(argv)
    if a.nightly:
        import arch_blind

        arch_blind.nightly()
        return 0
    if a.rollout:
        import arch_blind

        return arch_blind.rollout_cli(a.rollout)
    here = (
        Path(__file__).resolve().parents[2]
        if Path(__file__).resolve().parent.name == "arch-kit"
        else "."
    )
    if a.extract:
        import arch_extract

        return (
            arch_extract.extract_all(here)
            if a.coverage_all
            else arch_extract.extract_one(here)
        )
    if a.coverage_all:
        coverage_all(here)
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())


def ratchet(root):
    """Shrink the baseline to what still exists; never add. Returns (removed keys, removed legacy files)."""
    root = Path(root)
    canon = ac.load_canon(root)
    baseline = ac.load_baseline(root)
    viols, files, _ = current_violations(root, canon, baseline)
    cur = counts(viols)
    old = baseline.get("violations", {})
    new_counts = {k: min(n, cur.get(k, 0)) for k, n in old.items() if cur.get(k, 0)}
    sizes = {
        f: min(n, line_count(root, f))
        for f, n in baseline.get("legacy_files", {}).items()
        if f in set(files)
    }
    removed = (
        len(old) - len(new_counts),
        len(baseline.get("legacy_files", {})) - len(sizes),
    )
    baseline.update({"violations": new_counts, "legacy_files": sizes})
    ac.save_baseline(ac.arch_path(root, "baseline.json"), baseline)
    return removed


def tighten(root, rules, ref):
    """Make `rules` blocking: record today's violations of them as known (so only new ones fail), add them to
    `enforce`, and log the resolved decision that authorised it. Refuses without a resolved decision."""
    root = Path(root)
    if ac.decision_state(ref) != "tapped":
        raise ValueError(ac.decision_error(ref))
    if any(r.startswith(("canon.", "transition.")) for r in rules):
        raise ValueError(
            "ownership and transition violations cannot be baselined: fix them"
        )
    canon = ac.load_canon(root)
    baseline = ac.load_baseline(root)
    viols, _, _ = current_violations(root, canon, baseline)
    known = baseline.get("violations", {})
    for k, n in counts(viols).items():
        if any(k.split("|")[0] == r or k.startswith(r + ".") for r in rules):
            known[k] = max(n, known.get(k, 0))
    baseline["violations"] = known
    ac.save_baseline(ac.arch_path(root, "baseline.json"), baseline)
    canon["enforce"] = list(canon["enforce"]) + [
        r for r in rules if r not in canon["enforce"]
    ]
    ac.save_yaml(ac.arch_path(root, "canon.yaml"), canon)
    ac.log_decision(root, ref)


def build_baseline(root, canon):
    """Record today's state as the baseline (adopt only)."""
    viols, files, _ = current_violations(root, canon)
    legacy = (canon.get("layers") or {}).get("legacy", [])
    sizes = {
        f: line_count(root, f)
        for f in files
        if legacy and ac.matches(f, legacy) and f.endswith(ac.SOURCE_EXTS)
    }
    base = {
        "version": 1,
        "generated": ac.today().isoformat(),
        "violations": dict(counts(viols)),
        "legacy_files": sizes,
    }
    import arch_blind

    n = arch_blind.source_count(root)
    if not canon.get("capabilities") and n > arch_blind.EMPTY_REGISTER_MIN_FILES:
        base["register_empty"] = (
            n  # ownership not established at adoption: reported, may not double
        )
    return base
