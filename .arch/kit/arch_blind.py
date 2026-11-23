"""arch_blind: proves the architecture check could look: a coverage record per language, a verdict that never calls a big repository clean when it found nothing, and a seeded canary per language (SPEC-ARCH-CHECK-FINDS-DUPLICATES-ON-ITS-OWN)."""

import base64
import datetime as dt
import subprocess
import sys
import tempfile
from pathlib import Path

import arch_config as ac
import arch_literals as lit
import arch_scan as sc

# The exact grammar versions this check is pinned to (SPEC-ARCH-CHECK-FINDS-DUPLICATES-ON-ITS-OWN).
TREE_SITTER_PINS = {
    "tree_sitter": "0.25.2",
    "tree_sitter_typescript": "0.23.2",
    "tree_sitter_rust": "0.24.2",
    "tree_sitter_javascript": "0.25.0",
}

# extension -> (grammar module, factory returning the language capsule)
GRAMMARS = {
    ".tsx": ("tree_sitter_typescript", "language_tsx"),
    ".ts": ("tree_sitter_typescript", "language_typescript"),
    ".mts": ("tree_sitter_typescript", "language_typescript"),
    ".cts": ("tree_sitter_typescript", "language_typescript"),
    ".js": ("tree_sitter_javascript", "language"),
    ".mjs": ("tree_sitter_javascript", "language"),
    ".cjs": ("tree_sitter_javascript", "language"),
    ".jsx": ("tree_sitter_javascript", "language"),
    ".rs": ("tree_sitter_rust", "language"),
}

BIG_REPO_FILES = 50
check_balanced = lit.check_balanced  # the scanner lives in arch_literals (the spec's file list; blind stays under 600 lines)


def _first_error_line(node):
    """Line (1-based) of the first ERROR or missing node in the tree, or None when the tree is clean."""
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == "ERROR" or n.is_missing:
            return n.start_point[0] + 1
        stack.extend(n.children)
    return None


def parse_check(text, lang, rel):
    """Parse `text` with tree-sitter when the grammar for `rel`'s extension imports; raise
    SyntaxError('tree-sitter: syntax error at line N') on the first ERROR or missing node. Falls back to
    check_balanced when tree-sitter or the grammar is unavailable, or the extension is unknown. Never raises
    ImportError."""
    grammar = GRAMMARS.get(Path(rel).suffix.lower())
    if grammar is not None:
        module_name, factory = grammar
        try:
            import tree_sitter

            mod = __import__(module_name)
            language = tree_sitter.Language(getattr(mod, factory)())
            parser = tree_sitter.Parser(language)
            tree = parser.parse(text.encode("utf-8"))
        except ImportError:
            pass
        else:
            line = _first_error_line(tree.root_node)
            if line is not None:
                # the TypeScript grammar rejects some valid code (for example `x as T[] ?? []`), so an error only
                # counts when the bracket scanner also rejects the file
                try:
                    check_balanced(text, lang)
                except SyntaxError as e:
                    raise SyntaxError(
                        f"tree-sitter: syntax error at line {line} ({e})"
                    ) from None
            return
    check_balanced(text, lang)


def coverage_record(root):
    """{language: {seen, parsed, skipped: [(file, reason)]}}; test and generated files are counted as skipped with a reason."""
    rec = {}
    for rel, lang in lit.source_files(root):
        r = rec.setdefault(lang, {"seen": 0, "parsed": 0, "skipped": []})
        r["seen"] += 1
        if lit.TEST_RE.search(rel):
            r["skipped"].append((rel, "test file"))
            continue
        if lit.GENERATED_RE.search(rel):
            r["skipped"].append((rel, "generated"))
            continue
        try:
            lit.extract_file(root, rel, lang)
            r["parsed"] += 1
        except (SyntaxError, ValueError, UnicodeDecodeError, OSError) as e:
            r["skipped"].append((rel, f"could not parse: {e}"))
    return rec


def unparsed(rec):
    return [
        (f, why)
        for r in rec.values()
        for f, why in r["skipped"]
        if why.startswith("could not parse")
    ]


def coverage_text(name, rec):
    parts = [
        f"{lang} {r['parsed']}/{r['seen']} parsed" for lang, r in sorted(rec.items())
    ]
    if not parts:
        return "nothing to scan (no source files)"
    return f"scanned {name}: " + ", ".join(parts)


# One planted duplicate (same value, two files) and one planted divergence (two values) per language.
CANARY = {
    "python": {
        "a.py": "WIDGET_LIMIT_SECONDS = 45\nGADGET_RETRIES = 7\n",
        "b.py": "WIDGET_LIMIT_SECONDS = 45\nGADGET_RETRIES = 9\n",
    },
    "typescript": {
        "a.ts": "export const WIDGET_LIMIT_SECONDS = 45;\nexport const GADGET_RETRIES = 7;\n",
        "b.ts": "export const WIDGET_LIMIT_SECONDS = 45;\nexport const GADGET_RETRIES = 9;\n",
    },
    "rust": {
        "a.rs": "pub const WIDGET_LIMIT_SECONDS: u64 = 45;\npub const GADGET_RETRIES: u32 = 7;\n",
        "b.rs": "pub const WIDGET_LIMIT_SECONDS: u64 = 45;\npub const GADGET_RETRIES: u32 = 9;\n",
    },
}


def canary():
    """Languages whose extractor failed to find the planted duplicate and divergence. Empty list means all found."""
    missed = []
    for lang, files in CANARY.items():
        with tempfile.TemporaryDirectory() as d:
            for name, body in files.items():
                (Path(d) / name).write_text(body)
            cl = {c["id"]: c for c in lit.cluster(lit.extract(d))}
        dup, div = cl.get("limit-widget"), cl.get("gadget-retry")
        if not (dup and not dup["divergence"] and div and div["divergence"]):
            missed.append(lang)
    return missed


def verdict(root, clusters=None):
    """One honest status for a repository: clean, findings, unparsed, or ownership not established."""
    root = Path(root)
    rec = coverage_record(root)
    clusters = lit.cluster(lit.extract(root)) if clusters is None else clusters
    seen = sum(r["seen"] for r in rec.values())
    bad = unparsed(rec)
    canon = ac.load_canon(root) or {}
    registered = len(canon.get("capabilities") or {})
    missed = canary()
    if missed:
        status, why = (
            "blind",
            f"the extractor missed its planted canary in {', '.join(missed)}",
        )
    elif not seen:
        status, why = "nothing to scan", "no source files"
    elif bad:
        status, why = (
            "unparsed",
            "could not parse: " + "; ".join(f"{f} ({w})" for f, w in bad),
        )
    elif seen > BIG_REPO_FILES and not clusters and not registered:
        status, why = (
            "ownership not established",
            f"{seen} source files, 0 clusters and 0 registered jobs",
        )
    elif clusters:
        status, why = (
            "findings",
            f"{len(clusters)} clusters, {sum(c['divergence'] for c in clusters)} divergent",
        )
    else:
        status, why = "clean", f"{seen} source files scanned, no duplicates"
    return {
        "status": status,
        "why": why,
        # a repository with no source files has a stated reason, so it is not a failure
        "ok": status in ("clean", "findings", "nothing to scan"),
        "coverage": rec,
        "line": coverage_text(root.name, rec),
    }


# --- every active repository of the organisation: who lacks the register or the CI step, and the held rollout PRs ---
ORG = "Ant-vs-Bear"
ACTIVE_DAYS = 60
BRANCH = "chore/arch-check"
KIT = Path(__file__).resolve().parent
GH_CRED = [
    "-c",
    "credential.helper=",
    "-c",
    "credential.helper=!gh auth git-credential",
]


def gh(*args):
    run = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    return run.returncode, run.stdout


def active_repos(runner=gh, today=None, days=ACTIVE_DAYS):
    """Names of non-archived repositories pushed within `days` days, most recent first."""
    today = today or dt.datetime.now(dt.timezone.utc)
    code, out = runner(
        "api", "--paginate", f"orgs/{ORG}/repos?per_page=100&type=all",
        "--jq", '.[]|select(.archived==false)|"\\(.pushed_at)\\t\\(.name)"',
    )  # fmt: skip
    if code != 0:
        raise RuntimeError("could not list the organisation's repositories")
    rows = []
    for line in out.splitlines():
        pushed, _, name = line.partition("\t")
        if not name or not pushed:
            continue
        when = dt.datetime.fromisoformat(pushed.replace("Z", "+00:00"))
        if (today - when).days <= days:
            rows.append((pushed, name))
    return [n for _, n in sorted(rows, reverse=True)]


def _content(repo, path, runner):
    code, out = runner("api", f"repos/{ORG}/{repo}/contents/{path}", "--jq", ".content")
    if code != 0:
        return None
    try:
        return base64.b64decode(out).decode("utf-8", "replace")
    except ValueError:
        return ""


def has_register(repo, runner=gh):
    return _content(repo, ".arch/canon.yaml", runner) is not None


def has_ci_step(repo, runner=gh):
    code, out = runner(
        "api", f"repos/{ORG}/{repo}/contents/.github/workflows", "--jq", ".[].name"
    )
    if code != 0:
        return False
    for name in out.split():
        if name.endswith((".yml", ".yaml")) and "arch_kit" in (
            _content(repo, f".github/workflows/{name}", runner) or ""
        ):
            return True
    return False


def gap(repos=None, runner=gh):
    """Active repositories that lack the register or the CI step: [{repo, register, ci}]."""
    out = []
    for repo in repos if repos is not None else active_repos(runner):
        reg, ci = has_register(repo, runner), has_ci_step(repo, runner)
        if not (reg and ci):
            out.append({"repo": repo, "register": reg, "ci": ci})
    return out


VENDOR_RUFF = (
    "# Vendored architecture kit: a generated copy, not this repository's code.\n"
    'lint.select = []\nformat.exclude = ["*.py"]\n'
)


def write_place_plan(d):
    """The adoption's own generated files (.lifecycle/) are its place list, so the place check does not fail them."""
    import json

    pp = Path(d) / ".arch" / "plan.json"
    plan = json.loads(pp.read_text()) if pp.is_file() else {}
    place = plan.setdefault("place", [])
    if ".lifecycle/**" not in place:
        place.append(".lifecycle/**")
    pp.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")


def open_pr(repo, runner=gh):
    """True when a pull request from the rollout branch is already open in `repo`."""
    code, out = runner(
        "pr", "list", "--repo", f"{ORG}/{repo}", "--head", BRANCH, "--state", "open", "--json", "number"
    )  # fmt: skip
    return code == 0 and out.strip() not in ("", "[]")


def apply(rows, runner=gh):
    """Open one held pull request per gap repository. Returns [{repo, result}]."""
    results = []
    for row in rows:
        repo = row["repo"]
        if open_pr(repo, runner):
            results.append({"repo": repo, "result": "rollout PR already open"})
            continue
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / repo
            if subprocess.run(["git", "clone", "-q", "--depth", "1", f"https://github.com/{ORG}/{repo}.git", str(d)],
                              capture_output=True, check=False).returncode:  # fmt: skip
                results.append({"repo": repo, "result": "clone failed"})
                continue
            subprocess.run(
                ["git", "-C", str(d), "checkout", "-q", "-b", BRANCH],
                capture_output=True,
                check=False,
            )
            adopted = subprocess.run(
                [sys.executable, str(KIT / "arch_kit.py"), "adopt"],
                cwd=d,
                capture_output=True,
                text=True,
                check=False,
            )
            if (
                not adopted.returncode
            ):  # a repository's own ruff hooks must not lint the generated kit
                (d / ".arch" / "ruff.toml").write_text(VENDOR_RUFF)
                with open(d / ".arch" / "decisions.log", "a") as f:
                    f.write(f"{ac.today().isoformat()} {ADOPT_DECISION}\n")
                write_place_plan(d)
            if adopted.returncode:
                results.append(
                    {
                        "repo": repo,
                        "result": "adopt failed: " + adopted.stderr.strip()[-120:],
                    }
                )
                continue
            msg = "ci: architecture check that finds duplicates on its own (SPEC-ARCH-CHECK-FINDS-DUPLICATES-ON-ITS-OWN, Spec: avbos-systems#1286)\n\nCo-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
            failed = None
            for s in (
                ["add", "-A"],
                ["commit", "-q", "-m", msg],
                ["push", "-q", "-u", "origin", BRANCH],
            ):
                if subprocess.run(
                    ["git", "-C", str(d), *GH_CRED, *s],
                    capture_output=True,
                    check=False,
                ).returncode:
                    failed = s[0]
                    break
            if failed:
                results.append({"repo": repo, "result": f"git {failed} failed"})
                continue
            runner(
                "label",
                "create",
                "hold",
                "--repo",
                f"{ORG}/{repo}",
                "--color",
                "d93f0b",
                "--description",
                "do not auto-merge",
            )
            code, url = runner(
                "pr", "create", "--repo", f"{ORG}/{repo}", "--head", BRANCH,
                "--title", "ci: architecture check", "--label", "hold",
                "--body", "Adds .arch/ and the architecture CI step. Spec: avbos-systems#1286. Held: a workflow file is a CI file, the founder merges the held batch. Agents do not merge this PR.",
            )  # fmt: skip
            results.append(
                {
                    "repo": repo,
                    "result": url.strip() if code == 0 else "pr create failed",
                }
            )
    return results


def extract_one(root, out=print):
    """Coverage per language, the honest verdict, the clusters, and the ratchet result. Returns 0 only when all is well."""
    import arch_literals
    import arch_ratchet

    clusters = arch_literals.cluster(arch_literals.extract(root))
    v = verdict(root, clusters)
    out(v["line"])
    out(f"{Path(root).name}: {v['status']} ({v['why']})")
    for c in clusters[:15]:
        out("  " + arch_literals.report_line(c))
    fails = arch_ratchet.run(root, clusters, write=False)
    for f in fails:
        out("  FAIL " + f)
    return 0 if v["ok"] and not fails else 1


def extract_all(here, out=print):
    import arch_check

    """Every active repository of the organisation: who lacks the register or CI step, then each one's honest verdict."""

    try:
        names = active_repos()
    except RuntimeError:
        names = arch_check.COVERAGE_REPOS
    gaps = gap(names) if names is not arch_check.COVERAGE_REPOS else []
    for g in gaps:
        out(
            f"MISSING {g['repo']}: register {'yes' if g['register'] else 'no'}, CI step {'yes' if g['ci'] else 'no'}"
        )
    out(
        f"{len(gaps)} of {len(names)} active repositories lack the register or the CI step"
    )
    bad = len(gaps)
    for name in names:
        try:
            bad += extract_one(arch_check.repo_path(name, here), out) != 0
        except (RuntimeError, OSError, ValueError) as e:  # reported, never called clean
            out(f"{name}: could not be scanned ({e})")
            bad += 1
    return 1 if bad else 0


def merge_default(d, repo, runner=gh):
    """Merge the repository's default branch into the checked-out install branch, so the generated docs are checked
    against what the pull request will really merge into. Returns an error text, or None when merged or up to date."""
    code, out = runner("api", f"repos/{ORG}/{repo}", "--jq", ".default_branch")
    base = out.strip()
    if code or not base:
        return "could not read the default branch"
    git = [
        "git",
        "-C",
        str(d),
        "-c",
        "user.name=arch-kit rollout",
        "-c",
        "user.email=noreply@anthropic.com",
    ]
    if subprocess.run([*git, "fetch", "-q", "origin", base], capture_output=True, check=False).returncode:  # fmt: skip
        return "fetch of the default branch failed"
    if subprocess.run([*git, "merge", "-q", "--no-edit", f"origin/{base}"], capture_output=True, check=False).returncode:  # fmt: skip
        subprocess.run([*git, "merge", "--abort"], capture_output=True, check=False)
        return "merge conflict with the default branch: left alone"
    return None


def refresh(rows):
    """Bring each open rollout branch up to the current kit: decision logged, empty register baselined, kit synced.
    Plain pushes onto the branch of the open held PR; never merges. Returns [{repo, result}]."""
    import json

    results = []
    for row in rows:
        repo = row["repo"]
        if not open_pr(repo):
            results.append({"repo": repo, "result": "no open rollout PR"})
            continue
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / repo
            if subprocess.run(["git", "clone", "-q", "-b", BRANCH, f"https://github.com/{ORG}/{repo}.git", str(d)], capture_output=True, check=False).returncode:  # fmt: skip
                results.append({"repo": repo, "result": "clone failed"})
                continue
            merged = merge_default(d, repo)
            if merged:
                results.append({"repo": repo, "result": merged})
                continue
            run = subprocess.run([sys.executable, str(KIT / "arch_kit.py"), "adopt"], cwd=d, capture_output=True, text=True, check=False)  # fmt: skip
            if run.returncode:
                results.append(
                    {
                        "repo": repo,
                        "result": "adopt failed: " + run.stderr.strip()[-100:],
                    }
                )
                continue
            (d / ".arch" / "ruff.toml").write_text(VENDOR_RUFF)
            log = d / ".arch" / "decisions.log"
            if ADOPT_DECISION not in (log.read_text() if log.is_file() else ""):
                with open(log, "a") as f:
                    f.write(f"{ac.today().isoformat()} {ADOPT_DECISION}\n")
            write_place_plan(d)
            bp = d / ".arch" / "baseline.json"
            base = json.loads(bp.read_text())
            canon = ac.load_canon(d) or {}
            n = source_count(d)
            if not canon.get("capabilities") and n > EMPTY_REGISTER_MIN_FILES:
                base["register_empty"] = n
                bp.write_text(json.dumps(base, indent=2, sort_keys=True) + "\n")
            msg = "ci: log the adoption decision, baseline the empty register (SPEC-ARCH-CHECK-FINDS-DUPLICATES-ON-ITS-OWN, Spec: avbos-systems#1286)\n\nCo-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
            failed = None
            for st in (
                ["add", "-A"],
                ["commit", "-q", "-m", msg],
                ["push", "-q", "origin", BRANCH],
            ):
                if subprocess.run(["git", "-C", str(d), *GH_CRED, *st], capture_output=True, check=False).returncode:  # fmt: skip
                    failed = st[0]
                    break
            results.append(
                {
                    "repo": repo,
                    "result": f"git {failed} failed or nothing to change"
                    if failed
                    else "refreshed",
                }
            )
    return results


def rollout_cli(cmd):
    rows = gap()
    for r in rows:
        print(
            f"MISSING {r['repo']}: register {'yes' if r['register'] else 'no'}, CI step {'yes' if r['ci'] else 'no'}"
        )
    print(f"{len(rows)} active repositories lack the register or the CI step")
    if cmd == "refresh":
        for r in refresh(rows):
            print(f"{r['repo']}: {r['result']}")
    if cmd == "apply":
        for r in apply(rows):
            print(f"{r['repo']}: {r['result']}")
    return 1 if rows and cmd == "status" else 0


def nightly(out_dir=None, now=None):
    """The nightly list: write who lacks the check and a still-alive ping. Returns the number of gaps."""
    d = Path(out_dir or Path.home() / "logs")
    d.mkdir(parents=True, exist_ok=True)
    rows = gap()
    stamp = (now or dt.datetime.now().astimezone()).isoformat(timespec="seconds")
    lines = [
        f"{r['repo']}: register {'yes' if r['register'] else 'no'}, CI step {'yes' if r['ci'] else 'no'}"
        for r in rows
    ]
    (d / "arch-coverage-nightly.txt").write_text(
        f"{stamp} {len(rows)} active repositories lack the check\n"
        + "\n".join(lines)
        + "\n"
    )
    (d / "arch-coverage-nightly.alive").write_text(stamp)  # still-alive ping
    return len(rows)


EMPTY_REGISTER_MIN_FILES = 20
ADOPT_DECISION = "avbos-systems-1286-1795269465.decisions.json#d1"  # the founder's "open all 33" answer, 21 Nov 2026


def source_count(root):
    return len([f for f in ac.list_files(root) if f.endswith(ac.SOURCE_EXTS)])


def check_register(root, canon):
    """More than 20 source files and nothing registered guards nothing. A repository that adopted with an empty
    register has it recorded in the baseline: reported as 'ownership not established', and it fails only if the
    code has doubled since adoption. Anything else fails."""
    if canon.get("capabilities"):
        return []
    n = source_count(root)
    if n <= EMPTY_REGISTER_MIN_FILES:
        return []
    known = ac.load_baseline(root).get("register_empty")
    msg = f"{n} source files and 0 registered capabilities: the register guards nothing; register the jobs the code repeats"
    if known and n <= 2 * known:
        return [
            sc.violation(
                "note.ownership",
                ".arch/canon.yaml",
                "",
                f"ownership not established (known at adoption, {known} files): {msg}",
            )
        ]
    return [sc.violation("register.empty", ".arch/canon.yaml", "", msg)]
