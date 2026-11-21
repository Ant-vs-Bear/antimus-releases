"""arch_blind: proves the architecture check could look. A coverage record per language (files seen, parsed, skipped and
why), a verdict that never calls a big repository clean when it found nothing, and a seeded canary per language
(SPEC-ARCH-CHECK-FINDS-DUPLICATES-ON-ITS-OWN)."""

import base64
import datetime as dt
import subprocess
import sys
import tempfile
from pathlib import Path

import arch_config as ac
import arch_literals as lit

BIG_REPO_FILES = 50
OPEN, CLOSE = "([{", ")]}"
REGEX_PREV = set("(,=:[!&|?{};") | {""}


def check_balanced(text, lang):
    """Raise SyntaxError when strings, comments or brackets do not close: the file cannot be read as that language."""
    stack, i, n, prev = [], 0, len(text), ""
    while i < n:
        c = text[i]
        two = text[i : i + 2]
        if two == "//":
            i = text.find("\n", i)
            i = n if i < 0 else i
            continue
        if two == "/*":
            j = text.find("*/", i + 2)
            if j < 0:
                raise SyntaxError("unterminated block comment")
            i = j + 2
            continue
        if c == '"' or (c == "'" and lang == "typescript") or c == "`":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
                if c != "`" and j < n and text[j] == "\n":
                    break
            if j >= n or (c != "`" and text[j] == "\n"):
                raise SyntaxError("unterminated string")
            i, prev = j + 1, c
            continue
        if c == "/" and lang == "typescript" and prev in REGEX_PREV:
            j, cls = i + 1, False
            while j < n and text[j] != "\n" and (cls or text[j] != "/"):
                if text[j] == "\\":
                    j += 1
                elif text[j] == "[":
                    cls = True
                elif text[j] == "]":
                    cls = False
                j += 1
            if j < n and text[j] == "/":
                i, prev = j + 1, "x"
                continue
        if c in OPEN:
            stack.append(c)
        elif c in CLOSE and (not stack or OPEN.index(stack.pop()) != CLOSE.index(c)):
            raise SyntaxError(f"unmatched {c!r}")
        if not c.isspace():
            prev = c
        i += 1
    if stack:
        raise SyntaxError("unclosed bracket")


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
    return f"scanned {name}: " + (
        ", ".join(parts) or "no Python, TypeScript or Rust files"
    )


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
        "ok": status in ("clean", "findings"),
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


def apply(rows, runner=gh):
    """Open one held pull request per gap repository. Returns [{repo, result}]."""
    results = []
    for row in rows:
        repo = row["repo"]
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


def rollout_cli(cmd):
    rows = gap()
    for r in rows:
        print(
            f"MISSING {r['repo']}: register {'yes' if r['register'] else 'no'}, CI step {'yes' if r['ci'] else 'no'}"
        )
    print(f"{len(rows)} active repositories lack the register or the CI step")
    if cmd == "apply":
        for r in apply(rows):
            print(f"{r['repo']}: {r['result']}")
    return 1 if rows and cmd == "status" else 0
