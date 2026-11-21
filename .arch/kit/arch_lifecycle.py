"""arch_lifecycle: records of what a new feature replaces, and the check that keeps the old code gone (SPEC-SUPERSESSION).

One file per replacement: .lifecycle/replacements/<id>.yaml. `check` fails when a `deleted` target is still present or still
referenced, when a new reference to a `deprecated` target appears, or when a PR adds a route/page/table/cron with no record.
Static tools find unused code; this finds code that is still used but was superseded, because the replacing change says so.
A repo with no .lifecycle/ folder passes with nothing. Database objects are never deletable here: they can only be deprecated.
"""

import argparse
import datetime as dt
import fnmatch
import json
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import arch_config as ac

LIFE_DIR = ".lifecycle"
REC_DIR = ".lifecycle/replacements"
KINDS = {"path", "route", "flag", "env", "db-table", "db-column", "cron", "webhook"}
STATES = {"deleted", "deprecated"}
DB_KINDS = {"db-table", "db-column"}
MANUAL_KINDS = {"cron", "webhook"}
SKIP = (".lifecycle/", "docs/specs/archive/")
EXTRA_DIRS = ("supabase/", "docs/", "tests/", "e2e/")
EXTRA_FILES = ("vercel.json", ".env.example")
NEW_SURFACE = re.compile(
    r"(^|/)(route\.(ts|js)|page\.(tsx|jsx)|pages/api/.+\.(ts|js))$"
)


def _fail(rule, file, line, message):
    return {"rule": rule, "file": file, "line": line, "message": message}


def load_records(root):
    """([(file, record)], [failure]) for every .lifecycle/replacements/*.yaml."""
    root, recs, errs = Path(root), [], []
    seen = {}
    for p in sorted((root / REC_DIR).glob("*.y*ml")):
        rel = p.relative_to(root).as_posix()
        try:
            rec = yaml.safe_load(p.read_text()) or {}
        except yaml.YAMLError as e:
            errs.append(_fail("lifecycle.schema", rel, 1, f"{rel}: invalid yaml ({e})"))
            continue
        bad = _schema_errors(rec)
        if rec.get("id") in seen:
            bad.append(f"duplicate id {rec['id']!r} (also in {seen[rec['id']]})")
        if isinstance(rec, dict) and rec.get("id"):
            seen.setdefault(rec["id"], rel)
        errs += [_fail("lifecycle.schema", rel, 1, f"{rel}: {b}") for b in bad]
        if not bad:
            recs.append((rel, rec))
    return recs, errs


def _schema_errors(rec):
    if not isinstance(rec, dict) or not rec.get("id"):
        return ["a record needs an id"]
    out = []
    reps = rec.get("replaces")
    if reps == "none":
        for k in ("incumbent_search", "incumbent_found"):
            if not str(rec.get(k) or "").strip():
                out.append(f"`replaces: none` needs a non-empty {k}")
        return out
    if not isinstance(reps, list) or not reps:
        return ["replaces must be a list (or the string none)"]
    if not (rec.get("canonical") or {}).get("impl"):
        out.append("canonical.impl is required (what replaces it)")
    for r in reps:
        if not isinstance(r, dict) or not r.get("target"):
            out.append("each replaces entry needs a target")
        elif r.get("kind") not in KINDS:
            out.append(f"unknown kind {r.get('kind')!r} for {r['target']}")
        elif r.get("state") not in STATES:
            out.append(f"unknown state {r.get('state')!r} for {r['target']}")
    return out


def _entries(recs):
    for rel, rec in recs:
        if rec.get("replaces") != "none":
            for r in rec["replaces"]:
                yield rel, rec, r


def _strings(entry):
    """Exact strings that identify a target in other files."""
    t, kind = str(entry["target"]), entry["kind"]
    if kind == "path":
        base = t.rstrip("/")
        stem = re.sub(r"\.(tsx?|jsx?|py)$", "", base)
        return {base, stem}
    if kind == "route":
        m = re.search(r"(/\S*)", t)
        return {m.group(1) if m else t}
    if kind in DB_KINDS:
        return {t.split(".")[-1]}
    return {t}


def _in_target(entry, rel):
    if entry["kind"] != "path":
        return False
    t = str(entry["target"]).rstrip("/")
    return rel == t or rel.startswith(t + "/")


def _consumer_globs(entry):
    return [c for c in entry.get("consumers") or [] if "/" in str(c) or "*" in str(c)]


def _scan_files(root):
    files = [
        f for f in ac.list_files(root, ac.DEFAULT_IGNORE) if not f.startswith(SKIP)
    ]
    for p in Path(root).rglob("*"):
        rel = p.relative_to(root).as_posix()
        if (
            p.is_file()
            and (rel.startswith(EXTRA_DIRS) or rel in EXTRA_FILES)
            and rel not in files
            and not rel.startswith(SKIP)
            and "node_modules" not in rel
        ):
            files.append(rel)
    return files


def _grep(root, files, needle, skip=lambda r: False):
    hits = []
    for rel in files:
        if skip(rel):
            continue
        try:
            lines = (Path(root) / rel).read_text(errors="replace").splitlines()
        except OSError:
            continue
        hits += [(rel, i + 1) for i, ln in enumerate(lines) if needle in ln]
    return hits


def _diff_added(root, base):
    """{file: [(line_no, text)]} of lines added between base and HEAD."""
    out, cur, ln = {}, None, 0
    for line in ac.git(root, "diff", "-U0", f"{base}...HEAD").splitlines():
        if line.startswith("+++ b/"):
            cur = line[6:]
        elif line.startswith("@@"):
            m = re.search(r"\+(\d+)", line)
            ln = int(m.group(1)) if m else 0
        elif line.startswith("+") and cur and not line.startswith("+++"):
            out.setdefault(cur, []).append((ln, line[1:]))
            ln += 1
    return out


def _names(root, base, flt):
    return ac.git(
        root, "diff", "--name-only", f"--diff-filter={flt}", f"{base}...HEAD"
    ).split()


def _added_surface(root, base, added):
    names = _names(root, base, "A")
    hits = [n for n in names if NEW_SURFACE.search(n)]
    hits += [
        n
        for n in names
        if n.startswith("supabase/migrations/")
        and re.search(
            r"create\s+table",
            (Path(root) / n).read_text(errors="replace"),
            re.IGNORECASE,
        )
    ]
    if "vercel.json" in added and any(
        '"crons"' in t or '"path"' in t for _, t in added["vercel.json"]
    ):
        hits.append("vercel.json (cron)")
    return hits


def check(root, base=None):
    root = Path(root)
    recs, failures = load_records(root)
    warnings, manual = [], []
    if not (root / LIFE_DIR).is_dir() and not base:
        return {"ok": True, "failures": [], "warnings": [], "manual": []}
    files = _scan_files(root)
    added = _diff_added(root, base) if base else {}
    touched = (
        set(ac.git(root, "diff", "--name-only", f"{base}...HEAD").split())
        if base
        else set()
    )
    base_tree = (
        set(ac.git(root, "ls-tree", "-r", "--name-only", base).split())
        if base
        else set()
    )
    new_recs = set(_names(root, base, "A")) if base else set()
    for rel, rec in recs:
        if rec.get("replaces") == "none":
            continue
        for e in rec["replaces"]:
            failures += _check_entry(
                root,
                rel,
                rec,
                e,
                files,
                added,
                touched,
                base_tree,
                new_recs,
                base,
                warnings,
                manual,
            )
    if base:
        surf = _added_surface(root, base, added)
        changed = [t for t in touched if t.startswith(REC_DIR + "/")]
        if surf and not changed:
            failures.append(
                _fail(
                    "lifecycle.record-missing",
                    surf[0],
                    1,
                    f"{surf[0]}: this change adds a route, page, table or cron job but no record in {REC_DIR}/ "
                    "says what it replaces (write `replaces: none` with the search you ran if nothing)",
                )
            )
    return {
        "ok": not failures,
        "failures": failures,
        "warnings": warnings,
        "manual": manual,
    }


def _check_entry(
    root,
    rel,
    rec,
    e,
    files,
    added,
    touched,
    base_tree,
    new_recs,
    base,
    warnings,
    manual,
):
    out, state, kind = [], e["state"], e["kind"]
    target = str(e["target"])
    if kind in DB_KINDS and state == "deleted":
        out.append(
            _fail(
                "lifecycle.db-not-deletable",
                rel,
                1,
                f"{rel}: {target} is a database object; mark it deprecated and drop it in a separate approved migration",
            )
        )
    if kind in MANUAL_KINDS or kind in ("flag", "env"):
        manual.append(
            f"manual check needed: {kind} {target} ({rec['id']}): remove the provider or dashboard setting by hand"
        )
    if base and kind == "path" and rel in new_recs:
        stem = target.rstrip("/")
        if not any(f == stem or f.startswith(stem + "/") for f in base_tree):
            out.append(
                _fail(
                    "lifecycle.target-missing",
                    rel,
                    1,
                    f"{rel}: {target} does not exist on the base branch",
                )
            )
    if state == "deleted" and kind == "path":
        for f in files:
            if _in_target(e, f):
                out.append(
                    _fail(
                        "lifecycle.deleted-present",
                        f,
                        1,
                        f"{f}: listed as deleted by {rec['id']} but still exists",
                    )
                )
                break
    if state == "deleted" and kind not in DB_KINDS:
        for needle in _strings(e):
            for f, ln in _grep(root, files, needle, lambda r: _in_target(e, r)):
                out.append(
                    _fail(
                        "lifecycle.deleted-referenced",
                        f,
                        ln,
                        f"{f}:{ln}: still references {needle!r}, deleted by {rec['id']} (use {rec['canonical']['impl']})",
                    )
                )
    if state == "deprecated" and base:
        globs = _consumer_globs(e)
        for needle in _strings(e):
            for f, lines in added.items():
                if (
                    f.startswith(SKIP)
                    or _in_target(e, f)
                    or any(fnmatch.fnmatch(f, g) for g in globs)
                ):
                    continue
                out += [
                    _fail(
                        "lifecycle.deprecated-new-reference",
                        f,
                        ln,
                        f"{f}:{ln}: new reference to {needle!r}, deprecated by {rec['id']} (use {rec['canonical']['impl']})",
                    )
                    for ln, text in lines
                    if needle in text
                ]
    if state == "deprecated" and e.get("review_by"):
        due = (
            e["review_by"]
            if isinstance(e["review_by"], dt.date)
            else dt.date.fromisoformat(str(e["review_by"]))
        )
        if due < dt.datetime.now(dt.timezone.utc).date():
            hit = [t for t in touched if _in_target(e, t)] or [
                t for t in touched if any(n in t for n in _strings(e))
            ]
            msg = f"{rel}: review_by {due} has passed for {target}"
            (out if hit else warnings).append(
                _fail("lifecycle.overdue", rel, 1, msg) if hit else msg
            )
    return out


def _bans(recs, python):
    """Lint-ban entries for superseded path targets: Python ones when python is True, else JS/TS ones."""
    out = []
    for _, rec, e in _entries(recs):
        t = str(e["target"])
        if e["kind"] == "path" and t.endswith(".py") == python:
            out.append(
                {
                    "name": re.sub(r"\.(tsx?|jsx?|py)$", "", t.rstrip("/")),
                    "message": f"superseded by {rec['canonical']['impl']}: use that instead",
                }
            )
    return sorted(out, key=lambda b: b["name"])


def index_text(recs):
    lines = [
        "# Superseded code (generated from .lifecycle/replacements; do not edit)",
        "",
    ]
    for _, rec, e in sorted(
        _entries(recs), key=lambda x: (str(x[2]["target"]), x[1]["id"])
    ):
        lines.append(
            f"- {e['kind']} `{e['target']}` is {e['state']}: use `{rec['canonical']['impl']}` ({rec['id']})"
        )
    return "\n".join(lines) + "\n"


def gen(root):
    """Write INDEX.md and the lint-ban files when records exist. Returns the files written."""
    root = Path(root)
    recs, _ = load_records(root)
    if not recs:
        return []
    ts, py = _bans(recs, False), _bans(recs, True)
    body = {
        ".lifecycle/INDEX.md": index_text(recs),
        ".lifecycle/generated/eslint-restricted.json": json.dumps(
            {"no-restricted-imports": ["error", {"paths": ts}]},
            indent=1,
            sort_keys=True,
        )
        + "\n",
        ".lifecycle/generated/ruff-banned.json": json.dumps(
            {
                "banned-api": {
                    b["name"].replace("/", "."): {"msg": b["message"]} for b in py
                }
            },
            indent=1,
            sort_keys=True,
        )
        + "\n",
    }
    written = []
    for rel, text in body.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.is_file() or p.read_text() != text:
            p.write_text(text)
            written.append(rel)
    return written


def target_notice(root, rel, text):
    """Warning for an agent editing a superseded file or writing a reference to one; '' when unrelated."""
    try:
        recs, _ = load_records(root)
    except OSError:
        return ""
    for _, rec, e in _entries(recs):
        why = f"replaced by {rec['canonical']['impl']}" + (
            f": {e['reason']}" if e.get("reason") else ""
        )
        if _in_target(e, rel):
            return f"ARCHITECT: {rel} is {e['state']} ({why}); build on {rec['canonical']['impl']} instead"
        globs = _consumer_globs(e)
        if any(fnmatch.fnmatch(rel, g) for g in globs) or rel.startswith(SKIP):
            continue
        if any(n in text for n in _strings(e)):
            return f"ARCHITECT: {rel} refers to {e['target']}, which is {e['state']} ({why}); build on {rec['canonical']['impl']} instead"
    return ""


def format_result(res):
    lines = [
        f"{f['file']}:{f['line']}: [{f['rule']}] {f['message']}"
        for f in res["failures"]
    ]
    lines += [f"warning: {w}" for w in res["warnings"]] + list(res["manual"])
    return "\n".join(lines) or "lifecycle OK"


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in ("survey", "verify-survey", "verify-pilot"):
        import arch_lifecycle_survey as ls  # report-only survey and live checks (DOD-04 to DOD-06)

        return ls.main(argv)
    ap = argparse.ArgumentParser(prog="arch_lifecycle")
    ap.add_argument("action", choices=["check", "gen"])
    ap.add_argument("--root", default=".")
    ap.add_argument("--base")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.action == "gen":
        print("\n".join(gen(a.root)) or "lifecycle files already current")
        return 0
    res = check(a.root, a.base)
    print(json.dumps(res, indent=1) if a.json else format_result(res))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
