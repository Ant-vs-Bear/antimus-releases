"""arch_lifecycle_survey: read-only survey of superseded code already left in a repo (SPEC-SUPERSESSION, DOD-04 and DOD-05).

Writes ONLY a report outside the repo and never touches the working tree. Every finding is classed like arch_survey:
observed (measured), inferred (a name or heuristic) or unresolved (the founder decides). Names alone never make a finding
'observed'. Nothing is deleted; an accepted card becomes a normal replacement PR with a draft record.
"""

import datetime as dt
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import arch_config as ac
import arch_scan as sc
import arch_survey as sv

LEGACY_NAMES = {"legacy", "old", "deprecated", "v1", "_old", "obsolete"}
TWIN = re.compile(r"^(?P<stem>.+?)(?:[._-]?v2|[._-]?new|2)$", re.IGNORECASE)
ENTRY = re.compile(
    r"(^|/)(page|route|layout|loading|error|not-found|middleware|index|main|__init__|conftest|setup|config)\.\w+$"
    r"|(^|/)(tests?|e2e|scripts|docs|supabase|public)/|\.(test|spec|stories|d)\.\w+$|\.config\.\w+$"
)
FLAG_DEF = re.compile(r"\b((?:FEATURE|FLAG|ENABLE|USE)_[A-Z0-9_]{3,})\b")
ENV_LINE = re.compile(r"^([A-Z][A-Z0-9_]{2,})=", re.MULTILINE)
TABLE = re.compile(
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?:\w+\.)?\"?(\w+)\"?", re.IGNORECASE
)
RANK = {"observed": 0, "inferred": 1, "unresolved": 2}
MAX_CARDS = 10
REPORT_ROOT = Path.home() / ".local/share/lifecycle-survey"


def git_status(root):
    """Porcelain status without touching the index (a survey must leave the repo exactly as it found it)."""
    out = subprocess.run(
        ["git", "--no-optional-locks", "status", "--porcelain=v1"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    return out.stdout


def _finding(cls, kind, files, why, draft=None):
    return {"class": cls, "kind": kind, "files": files, "why": why, "draft": draft}


def _read(root, rel):
    try:
        return (Path(root) / rel).read_text(errors="replace")
    except OSError:
        return ""


def tracked(root):
    names = ac.git(root, "ls-files").splitlines()
    return [n for n in names if not ac.matches(n, ac.DEFAULT_IGNORE)]


def legacy_folders(src):
    groups = {}
    for f in src:
        parts = f.split("/")[:-1]
        for i, seg in enumerate(parts):
            if seg.lower() in LEGACY_NAMES:
                groups.setdefault("/".join(parts[: i + 1]), []).append(f)
                break
    return [
        _finding(
            "inferred",
            "legacy-folder",
            [d],
            f"folder named '{d.split('/')[-1]}' holds {len(fs)} source file(s); the name suggests it is superseded",
        )
        for d, fs in sorted(groups.items())
    ]


def _age(root, rel):
    ts = ac.git(root, "log", "-1", "--format=%cs", "--", rel).strip()
    return ts or "unknown"


def twins(root, src, inbound):
    by_dir, out = {}, []
    for f in src:
        if f.startswith("docs/"):
            continue
        p = Path(f)
        by_dir.setdefault(p.parent.as_posix(), {})[p.stem + p.suffix] = f
    for names in by_dir.values():
        stems = {Path(n).stem: f for n, f in names.items()}
        for stem, newer in sorted(stems.items()):
            m = TWIN.match(stem)
            older = stems.get(m.group("stem")) if m else None
            if not older or older == newer:
                continue
            both = inbound.get(older, 0) > 0 and inbound.get(newer, 0) > 0
            why = f"{newer} (last change {_age(root, newer)}) sits beside {older} (last change {_age(root, older)})"
            out.append(
                _finding(
                    "observed" if both else "inferred",
                    "twin",
                    [older, newer],
                    why
                    + (
                        "; both are imported by other files, so two live versions exist"
                        if both
                        else ""
                    ),
                    {
                        "id": f"{Path(newer).stem.lower()}-replaces-{Path(older).stem.lower()}",
                        "canonical": {"impl": newer},
                        "replaces": [
                            {"kind": "path", "target": older, "state": "deleted"}
                        ],
                    },
                )
            )
    return out


def is_script(root, f):
    """A Python file with a __main__ guard is run directly, so nothing needs to import it."""
    return f.endswith(".py") and "__main__" in _read(root, f)


def orphans(root, src, inbound):
    files = [
        f
        for f in src
        if not ENTRY.search(f) and inbound.get(f, 0) == 0 and not is_script(root, f)
    ]
    if not files:
        return []
    return [
        _finding(
            "unresolved",
            "orphan-files",
            sorted(files)[:50],
            f"{len(files)} source file(s) are imported by nothing; they may be loaded dynamically or by name",
        )
    ]


def env_and_flags(root, src):
    text = {f: _read(root, f) for f in src}
    env_example = next(
        (f for f in (".env.example", ".env.sample") if (Path(root) / f).is_file()), None
    )
    blob = "\n".join(text.values())
    out = []
    names = ENV_LINE.findall(_read(root, env_example)) if env_example else []
    dead = [n for n in names if n not in blob]
    if dead:
        out.append(
            _finding(
                "observed",
                "unused-env",
                [env_example],
                f"listed in {env_example} but read by no source file: {', '.join(dead)}",
            )
        )
    defined = {}
    for f, t in text.items():
        for m in FLAG_DEF.findall(t):
            defined.setdefault(m, set()).add(f)
    lonely = sorted(
        n
        for n, fs in defined.items()
        if len(fs) == 1 and len(re.findall(rf"\b{n}\b", blob)) == 1
    )
    if lonely:
        out.append(
            _finding(
                "observed",
                "unused-flag",
                sorted({next(iter(defined[n])) for n in lonely}),
                f"flag names that appear once and are never read: {', '.join(lonely)}",
            )
        )
    return out


def db_tables(root, src):
    migrations = [
        f
        for f in ac.git(root, "ls-files", "supabase/migrations").splitlines()
        if f.endswith(".sql")
    ]
    if not migrations:
        return []
    blob = "\n".join(_read(root, f) for f in src)
    tables = {t for m in migrations for t in TABLE.findall(_read(root, m))}
    dead = sorted(t for t in tables if not re.search(rf"\b{re.escape(t)}\b", blob))
    return (
        [
            _finding(
                "unresolved",
                "unused-table",
                migrations[:5],
                f"tables created by migrations that no source file names: {', '.join(dead)}",
            )
        ]
        if dead
        else []
    )


def tool_reports(root):
    """knip (only where a knip.json exists) and vulture (only if installed): one inferred card each, never a failure."""
    out = []
    if (Path(root) / "knip.json").is_file() and shutil.which("npx"):
        run = subprocess.run(
            ["npx", "--no-install", "knip", "--reporter", "compact"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        lines = [ln for ln in run.stdout.splitlines() if ln.strip()][:30]
        if lines:
            out.append(
                _finding(
                    "inferred",
                    "knip",
                    ["knip.json"],
                    "knip reports unused code (may be used dynamically): "
                    + "; ".join(lines[:10]),
                )
            )
    if shutil.which("vulture") and any(
        f.endswith(".py") for f in ac.git(root, "ls-files").splitlines()[:5000]
    ):
        run = subprocess.run(
            ["vulture", ".", "--min-confidence", "90"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        lines = [ln for ln in run.stdout.splitlines() if ln.strip()][:10]
        if lines:
            out.append(
                _finding(
                    "inferred",
                    "vulture",
                    [],
                    "vulture (90%+ confidence): " + "; ".join(lines),
                )
            )
    return out


def survey_repo(root):
    """Read-only. Returns {repo, findings (ranked, at most MAX_CARDS), total, status_before, status_after}."""
    root = Path(root)
    before = git_status(root)
    src = [f for f in tracked(root) if f.endswith(ac.SOURCE_EXTS)]
    canon = {"aliases": sv.STACK_DEFAULTS[sv.detect_stack(root)]["aliases"]}
    inbound = {}
    for _, to in sc.edges(root, src, canon):
        inbound[to] = inbound.get(to, 0) + 1
    found = (
        legacy_folders(src) + twins(root, src, inbound) + orphans(root, src, inbound)
    )
    found += env_and_flags(root, src) + db_tables(root, src) + tool_reports(root)
    found.sort(key=lambda f: (RANK[f["class"]], f["kind"], f["files"]))
    return {
        "repo": root.name,
        "total": len(found),
        "findings": found[:MAX_CARDS],
        "status_before": before,
        "status_after": git_status(root),
    }


def page(res):
    lines = [
        f"# Superseded-code survey: {res['repo']}",
        "",
        f"{res['total']} finding(s); showing the top {len(res['findings'])}.",
        "",
    ]
    for i, f in enumerate(res["findings"], 1):
        lines += [f"## {i}. [{f['class']}] {f['kind']}", f["why"], ""] + [
            f"- `{p}`" for p in f["files"]
        ]
        if f["draft"]:
            lines += [
                "",
                "Draft record (save as `.lifecycle/replacements/<id>.yaml` if you accept):",
                "```yaml",
                json.dumps(f["draft"], indent=1),
                "```",
            ]
        lines.append("")
    return "\n".join(lines) + "\n"


def run_dir(day=None):
    return REPORT_ROOT / (day or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d"))


def write_report(res, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{res['repo']}.md").write_text(page(res))
    (out_dir / f"{res['repo']}.json").write_text(json.dumps(res, indent=1) + "\n")


def repos_with_remote(projects=None):
    base = Path(projects) if projects else Path.home() / "projects"
    out = []
    for d in sorted(p for p in base.iterdir() if (p / ".git").exists()):
        if ac.git(d, "remote").strip():
            out.append(d)
    return out


def survey_all(projects=None, out_dir=None):
    out_dir = out_dir or run_dir()
    done = []
    for d in repos_with_remote(projects):
        res = survey_repo(d)
        write_report(res, out_dir)
        done.append(res["repo"])
    return done


def verify_survey(projects=None, out_dir=None):
    """(ok, messages): a report exists for every repo with a remote, and none of them changed its repo while surveying."""
    out_dir = out_dir or run_dir()
    msgs = []
    for d in repos_with_remote(projects):
        f = out_dir / f"{d.name}.json"
        if not f.is_file():
            msgs.append(f"{d.name}: no report in {out_dir}")
            continue
        res = json.loads(f.read_text())
        if res["status_before"] != res["status_after"]:
            msgs.append(f"{d.name}: the working tree changed during the survey")
    return not msgs, msgs or [
        "every repo with a remote has a report and none was changed by it"
    ]


PILOT_REPO = "Ant-vs-Bear/avbos-systems"
PILOT_WORKFLOW = ".github/workflows/lifecycle.yml"
PILOT_PREFIX = "lifecycle-pilot-fixture"


def _gh(*args):
    run = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    return run.returncode, run.stdout


def verify_pilot():
    """(ok, messages): the workflow is on the pilot's default branch, and a closed, unmerged fixture PR failed its `lifecycle` check."""
    code, _ = _gh(
        "api", f"repos/{PILOT_REPO}/contents/{PILOT_WORKFLOW}", "--jq", ".name"
    )
    if code != 0:
        return False, [f"{PILOT_WORKFLOW} is not on {PILOT_REPO}'s default branch"]
    code, out = _gh(
        "pr", "list", "--repo", PILOT_REPO, "--state", "closed", "--limit", "1000",
        "--json", "number,mergedAt,headRefName,headRefOid",
    )  # fmt: skip
    prs = [
        p for p in json.loads(out or "[]") if p["headRefName"].startswith(PILOT_PREFIX)
    ]
    for pr in prs:
        if pr["mergedAt"]:
            return False, [
                f"fixture PR {PILOT_REPO}#{pr['number']} was merged; it must be closed unmerged"
            ]
        code, runs = _gh(
            "api",
            f"repos/{PILOT_REPO}/commits/{pr['headRefOid']}/check-runs",
            "--jq",
            '.check_runs[] | select(.name=="lifecycle") | .conclusion',
        )
        if "failure" in runs.split():
            return True, [
                f"{PILOT_REPO}#{pr['number']}: the real workflow rejected the fixture PR, which was then closed unmerged"
            ]
    return False, [
        f"no closed fixture PR (branch {PILOT_PREFIX}*) with a failed `lifecycle` check in {PILOT_REPO}"
    ]


def main(argv):
    action = argv[0] if argv else ""
    if action == "verify-pilot":
        ok, msgs = verify_pilot()
        print("\n".join(msgs))
        return 0 if ok else 1
    if action == "survey":
        paths = [a for a in argv[1:] if not a.startswith("--")]
        if "--all" in argv or not paths:
            print("surveyed:", ", ".join(survey_all()), "->", run_dir())
        else:
            for p in paths:
                res = survey_repo(p)
                write_report(res, run_dir())
                print(page(res))
        return 0
    ok, msgs = verify_survey()
    print("\n".join(msgs))
    return 0 if ok else 1
