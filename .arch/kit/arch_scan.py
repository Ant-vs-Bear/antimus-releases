"""arch_scan: deterministic scanners for the chief architect (SPEC-CHIEF-ARCHITECT section 5.3).

Import edges (TS/JS and Python), canon bans, copy-paste detection by token windows, loose files.
Each scanner returns plain violation dicts: {rule, path, target, detail, key}; the key is the identity used by the
set-based baseline, so deleting one old violation never frees a slot for a new one.
"""

import ast
import posixpath
import re
import zlib
from pathlib import Path

from arch_config import SOURCE_EXTS, matches

JS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
JS_IMPORT = re.compile(
    r"""(?:import|export)\s[^'"`;]*?from\s*['"]([^'"]+)['"]|import\s*['"]([^'"]+)['"]"""
    r"""|require\(\s*['"]([^'"]+)['"]\s*\)|import\(\s*['"]([^'"]+)['"]\s*\)""",
    re.DOTALL,
)
DEFAULT_ALIASES = {"@/": ["src/", ""]}
MIN_UNIQUE = 12  # a window with fewer distinct tokens is boilerplate, not a clone
MAX_SHARERS = 8  # a window shared by more files is a header/boilerplate
TOKEN_RE = re.compile(r"[A-Za-z_]\w*|\d+(?:\.\d+)?|\"[^\"\n]*\"|'[^'\n]*'|`[^`]*`|\S")
MOD = (1 << 61) - 1


def violation(rule, path, target="", detail=""):
    return {
        "rule": rule,
        "path": path,
        "target": target,
        "detail": detail,
        "key": f"{rule}|{path}|{target}",
    }


def read_text(root, rel):
    try:
        return (Path(root) / rel).read_text(errors="replace")
    except OSError:
        return ""


def js_specs(text):
    return [next(g for g in m.groups() if g) for m in JS_IMPORT.finditer(text)]


def resolve_js(frm, spec, canon, fileset):
    aliases = canon.get("aliases") or DEFAULT_ALIASES
    cands = []
    if spec.startswith("."):
        cands.append(posixpath.normpath(posixpath.join(posixpath.dirname(frm), spec)))
    else:
        for prefix, bases in aliases.items():
            if spec.startswith(prefix):
                rest = spec[len(prefix) :]
                cands += [
                    posixpath.normpath(posixpath.join(b, rest))
                    for b in ([bases] if isinstance(bases, str) else bases)
                ]
    for c in cands:
        stem = (
            posixpath.splitext(c)[0]
            if c.endswith((".js", ".jsx", ".mjs", ".cjs"))
            else None
        )
        # TypeScript ESM writes './foo.js' for the source file foo.ts
        alts = [stem + e for e in JS_EXTS] if stem else []
        for opt in (
            [c] + alts + [c + e for e in JS_EXTS] + [c + "/index" + e for e in JS_EXTS]
        ):
            if opt in fileset:
                return opt
    return None


def py_modules(text, frm):
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            out += [(0, a.name) for a in n.names]
        elif isinstance(n, ast.ImportFrom):
            base = n.module or ""
            out += [(n.level, base)] + [
                (n.level, f"{base}.{a.name}".strip(".")) for a in n.names
            ]
    return out


def resolve_py(frm, level, module, fileset):
    parts = module.split(".") if module else []
    bases = (
        [""]
        if level == 0
        else [
            posixpath.normpath(
                posixpath.join(posixpath.dirname(frm), *([".."] * (level - 1)))
            )
        ]
    )
    if level == 0:
        bases += ["src"]
    for b in bases:
        p = posixpath.normpath(posixpath.join(b, *parts)) if parts else b
        for cand in (p + ".py", p + "/__init__.py"):
            if cand in fileset and cand != frm:
                return cand
    return None


def edges(root, files, canon):
    """Internal import edges (src, dst) between repo files."""
    fileset = set(files)
    out = set()
    for f in files:
        if not f.endswith(SOURCE_EXTS):
            continue
        text = read_text(root, f)
        if f.endswith(JS_EXTS):
            for spec in js_specs(text):
                dst = resolve_js(f, spec, canon, fileset)
                if dst and dst != f:
                    out.add((f, dst))
        else:
            for level, mod in py_modules(text, f):
                dst = resolve_py(f, level, mod, fileset)
                if dst:
                    out.add((f, dst))
    return sorted(out)


def layer_violations(edge_list, canon):
    layers = canon.get("layers") or {}
    legacy, new = layers.get("legacy", []), layers.get("new", [])
    if not legacy:
        return []
    out = []
    for src, dst in edge_list:
        if (
            matches(dst, legacy)
            and not matches(src, legacy)
            and (not new or matches(src, new))
        ):
            out.append(
                violation(
                    "layer.new-to-legacy", src, dst, f"{src} imports legacy {dst}"
                )
            )
    return out


def ban_lines(text, pattern):
    """(line number, line text) for every line that matches a ban pattern (substring, or regex when prefixed re:)."""
    rx = re.compile(pattern[3:]) if pattern.startswith("re:") else None
    return [
        (n, ln)
        for n, ln in enumerate(text.split("\n"), 1)
        if (rx.search(ln) if rx else pattern in ln)
    ]


def ban_violations(root, files, canon):
    """One violation per matching line. The key carries a hash of the line text so the baseline can count occurrences."""
    out = []
    for cap, spec in (canon.get("capabilities") or {}).items():
        bans = spec.get("bans") or []
        canonical = spec.get("canonical")
        canonical = [canonical] if isinstance(canonical, str) else (canonical or [])
        scope, allow = spec.get("scope"), spec.get("allow", [])
        for f in files:
            if (
                not f.endswith(SOURCE_EXTS)
                or f in [c.split("#")[0] for c in canonical]
                or matches(f, allow)
            ):
                continue
            if scope and not matches(f, scope):
                continue
            text = read_text(root, f)
            for pat in bans:
                for line_no, line in ban_lines(text, pat):
                    hint = (
                        f"use {canonical[0].split('#')[0]}"
                        if canonical
                        else "use the canonical module"
                    )
                    v = violation(
                        f"canon.{cap}",
                        f,
                        pat,
                        f"{f}:{line_no}: '{pat}' is banned for {cap}; {hint}",
                    )
                    v["key"] = (
                        f"canon.{cap}|{f}|{pat}|{zlib.crc32(line.strip().encode()):08x}"
                    )
                    out.append(v)
    return out


def tokens_of(text, ext):
    if ext == ".py":
        text = re.sub(r"#[^\n]*", "", text)
    else:
        text = re.sub(
            r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.DOTALL
        )
        text = re.sub(r"//[^\n]*", "", text)
    toks = []
    for ln, line in enumerate(text.split("\n"), 1):
        if (
            re.match(r"\s*(import|from|export\s+\*|export\s+\{[^}]*\}\s+from)\b", line)
            or "require(" in line
        ):
            continue
        toks += [(t, ln) for t in TOKEN_RE.findall(line)]
    return toks


def window_hashes(toks, n):
    if len(toks) < n:
        return []
    vals = [
        zlib.crc32(t.encode()) for t, _ in toks
    ]  # stable across runs (builtin hash() is randomised)
    base, h, out = 1000003, 0, []
    top = pow(base, n, MOD)
    for i, v in enumerate(vals):
        h = (h * base + v) % MOD
        if i >= n:
            h = (h - vals[i - n] * top) % MOD
        if i >= n - 1:
            out.append(h)
    return out


def clones(root, files, canon):
    """Type-1 clones across different files (identical token sequences of at least min_tokens)."""
    n = int(canon.get("dup", {}).get("min_tokens", 60))
    ignore = canon.get("dup", {}).get("ignore_names", [])
    index = {}
    toks_by = {}
    for f in files:
        if not f.endswith(SOURCE_EXTS) or matches(f, ignore):
            continue
        toks = tokens_of(read_text(root, f), posixpath.splitext(f)[1])
        toks_by[f] = toks
        for i, h in enumerate(window_hashes(toks, n)):
            if len({t for t, _ in toks[i : i + n]}) >= MIN_UNIQUE:
                index.setdefault(h, []).append((f, i))
    pairs = {}
    for h, locs in index.items():
        if len({f for f, _ in locs}) < 2 or len(locs) > MAX_SHARERS:
            continue
        for a in range(len(locs)):
            for b in range(a + 1, len(locs)):
                (fa, ia), (fb, ib) = sorted([locs[a], locs[b]])
                if fa != fb:
                    pairs.setdefault((fa, fb), []).append((ia, ib, h))
    out = []
    for (fa, fb), ms in sorted(pairs.items()):
        ms.sort()
        region = [ms[0]]
        for m in ms[1:] + [None]:
            if m and m[0] - region[-1][0] == 1 and m[1] - region[-1][1] == 1:
                region.append(m)
                continue
            ia, ib, h = region[0]
            la, lb = toks_by[fa][ia][1], toks_by[fb][ib][1]
            out.append(
                violation(
                    "dup",
                    fa,
                    fb,
                    f"{fa}:{la} and {fb}:{lb} share {len(region) + n - 1} identical tokens",
                )
                | {"key": f"dup|{fa}|{fb}|{h % 10**8}"}
            )
            region = [m] if m else []
    return out


ROOT_OK = re.compile(
    r"^(README|CLAUDE|LICENSE|CHANGELOG|CONTRIBUTING|SECURITY|CODEOWNERS|AGENTS)(\.md)?$|^\.|^(package(-lock)?\.json|tsconfig.*\.json|"
    r"pyproject\.toml|uv\.lock|Dockerfile.*|docker-compose.*|.*\.config\.(js|ts|mjs|cjs)|app\.json|eas\.json|vercel\.json)$",
    re.IGNORECASE,
)


def loose_violations(files, canon):
    loose = canon.get("loose") or {}
    allow = set(loose.get("root_allow", []))
    out = []
    for f in files:
        if (
            "/" not in f
            and f.endswith(".md")
            and f not in allow
            and not ROOT_OK.match(f)
        ):
            out.append(
                violation(
                    "loose.root",
                    f,
                    "",
                    f"{f}: analysis/summary document at the repo root; put it under docs/",
                )
            )
    for d in loose.get("flat_dirs", []):
        d = d.rstrip("/")
        direct = [
            f for f in files if posixpath.dirname(f) == d and f.endswith(SOURCE_EXTS)
        ]
        has_domains = any(
            f.startswith(d + "/") and posixpath.dirname(f) != d for f in files
        )
        if has_domains:
            out += [
                violation(
                    "loose.flat",
                    f,
                    "",
                    f"{f}: loose file at the flat root of {d}; use a domain folder",
                )
                for f in direct
            ]
    return out
