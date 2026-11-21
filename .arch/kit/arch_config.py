"""arch_config: the chief architect's policy files and shared helpers (SPEC-CHIEF-ARCHITECT section 5.2).

Per repo, under .arch/:
  canon.yaml       normative: capabilities (canonical module per job), layers, ignore lists, enforcement choices
  baseline.json    GENERATED set of today's individual violations (rule + path + target); only ever shrinks
  exceptions.yaml  founder-approved, scoped, expiring exceptions
  decisions.log    append-only record of decision references that authorised a policy change
  pending.json     exception requests waiting for the founder (asynchronous flow)
  plan.json        the architecture plan for the feature being built
"""

import datetime as dt
import functools
import json
import os
import re
import subprocess
import time
from pathlib import Path

import yaml

ARCH_DIR = ".arch"
SOURCE_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py")
DEFAULT_IGNORE = [
    "node_modules/**",
    "**/node_modules/**",
    ".next/**",
    "**/.next/**",
    "dist/**",
    "**/dist/**",
    "build/**",
    "**/build/**",
    ".git/**",
    ".worktrees/**",
    "**/.worktrees/**",
    "coverage/**",
    "**/__pycache__/**",
    ".venv/**",
    "venv/**",
    "ios/**",
    "android/**",
    ".arch/**",
    ".spec-gate/**",
    ".spec-evidence/**",
    # The WIP gate (SPEC-WIP-ROLLOUT) is generated infrastructure, not product code; exempt in every repo (founder 2026-10-26).
    ".github/wip-gate/**",
    ".github/workflows/wip-*.yml",
    "**/*.min.js",
    "package-lock.json",
    "uv.lock",
    "**/*.lock",
]
# Edit-time blocks and gates that fail by default (decision d1); everything else warns until the founder tightens it.
DEFAULT_ENFORCE = [
    "legacy.new-file",
    "layer.new-to-legacy",
    "legacy.growth",
    "gen.stale",
    "policy",
    "pending.awaiting",
    "place",
    "exception.expired",
]
DEFAULT_DUP_IGNORE = [
    "**/route.ts",
    "**/route.js",
    "**/page.tsx",
    "**/page.ts",
    "**/layout.tsx",
    "**/*.test.*",
    "**/*.spec.*",
    "**/__tests__/**",
    "tests/**",
    "**/migrations/**",
    "**/*.d.ts",
]
GRACE_DAYS = 7


@functools.lru_cache(maxsize=512)
def glob_re(pat):
    """Glob with ** support; parentheses and brackets are literal (Next.js route groups like app/(lite))."""
    i, out = 0, ""
    while i < len(pat):
        if pat.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
            continue
        if pat.startswith("**", i):
            out += ".*"
            i += 2
            continue
        c = pat[i]
        out += "[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c)
        i += 1
    return re.compile("^" + out + "$")


def matches(path, patterns):
    return any(glob_re(p).match(path) for p in patterns or [])


def today():
    return dt.datetime.now().astimezone().date()


def git(root, *args):
    r = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=False
    )
    return r.stdout if r.returncode == 0 else ""


def list_files(root, extra_ignore=()):
    """Tracked + untracked, non-ignored files as POSIX relative paths."""
    root = Path(root)
    out = git(root, "ls-files", "-co", "--exclude-standard", "-z")
    paths = (
        [p for p in out.split("\0") if p]
        if out
        else [
            str(p.relative_to(root))
            for p in root.rglob("*")
            if p.is_file() and ".git" not in p.parts
        ]
    )
    ign = DEFAULT_IGNORE + list(extra_ignore)
    return sorted(p for p in paths if not matches(p, ign) and (root / p).is_file())


def source_files(root, canon):
    roots = canon.get("roots") or []
    return [
        p
        for p in list_files(root, canon.get("ignore", []))
        if p.endswith(SOURCE_EXTS)
        and (
            not roots or any(p == r or p.startswith(r.rstrip("/") + "/") for r in roots)
        )
    ]


def arch_path(root, name):
    return Path(root) / ARCH_DIR / name


def load_canon(root):
    p = arch_path(root, "canon.yaml")
    if not p.is_file():
        return None
    c = yaml.safe_load(p.read_text()) or {}
    c.setdefault("capabilities", {})
    c.setdefault("layers", {})
    c.setdefault("ignore", [])
    c.setdefault("aliases", {})
    c.setdefault("loose", {})
    c.setdefault("enforce", list(DEFAULT_ENFORCE))
    dup = c.setdefault("dup", {})
    dup.setdefault("min_tokens", 60)
    dup.setdefault("ignore_names", list(DEFAULT_DUP_IGNORE))
    return c


def save_yaml(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))


def load_json(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return default


def save_json(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")


def save_baseline(path, data):
    """One line per section so a baseline of thousands of entries stays reviewable and under the size gate."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    body = ",\n".join(
        f" {json.dumps(k)}: {json.dumps(v, sort_keys=True, separators=(',', ':'))}"
        for k, v in sorted(data.items())
    )
    Path(path).write_text("{\n" + body + "\n}\n")


def load_baseline(root):
    return load_json(
        arch_path(root, "baseline.json"),
        {"version": 1, "violations": [], "legacy_files": {}},
    )


def load_exceptions(root):
    p = arch_path(root, "exceptions.yaml")
    return (
        (yaml.safe_load(p.read_text()) or {}).get("exceptions", [])
        if p.is_file()
        else []
    )


def decisions_dir():
    return Path(
        os.environ.get("AVB_DECISIONS_DIR") or Path.home() / ".avb" / "decisions"
    )


def resolve_decision_ref(ref):
    """'<file>#<id>' -> the resolved decision dict, or None if the file/decision is missing or unanswered."""
    name, _, did = (ref or "").partition("#")
    data = load_json(decisions_dir() / name) if name else None
    if not data or data.get("status") not in ("resolved", "applied"):
        return None
    for d in data.get("decisions", []):
        if d.get("id") == did and d.get("answer"):
            return d
    return None


def decision_refs_logged(root):
    p = arch_path(root, "decisions.log")
    return (
        [ln.split()[-1] for ln in p.read_text().splitlines() if ln.strip()]
        if p.is_file()
        else []
    )


def log_decision(root, ref):
    if resolve_decision_ref(ref) is None:
        raise ValueError(
            f"decision {ref!r} is not a resolved decision on the decisions page"
        )
    p = arch_path(root, "decisions.log")
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a") as f:
        f.write(f"{time.strftime('%Y-%m-%d')} {ref}\n")


def default_branch(root):
    ref = git(root, "symbolic-ref", "--short", "refs/remotes/origin/HEAD").strip()
    if ref:
        return ref
    for cand in ("origin/main", "origin/master", "main", "master"):
        if git(root, "rev-parse", "--verify", "-q", cand).strip():
            return cand
    return "HEAD"


def base_ref(root, explicit=None):
    if explicit:
        return explicit
    b = default_branch(root)
    return git(root, "merge-base", "HEAD", b).strip() or "HEAD"


def changed_files(root, base):
    """(added, modified) relative paths since base, including staged, unstaged and untracked work."""
    added, modified = set(), set()
    for ln in git(root, "diff", "--name-status", base).splitlines():
        st, _, path = ln.partition("\t")
        (added if st.startswith("A") else modified).add(path.split("\t")[-1])
    for p in git(root, "ls-files", "-o", "--exclude-standard", "-z").split("\0"):
        if p:
            added.add(p)
    return sorted(added), sorted(modified - added)
