"""arch_hooks: edit-time and stop-time behaviour (SPEC-CHIEF-ARCHITECT sections 5.5, 5.8, 5.11).

Block exactly three things at edit time (a new file under a legacy path, a new import from new code into legacy, growth of a
legacy file) plus writes to the policy files; everything else is a warning, capped at three rules. `file_findings` is the one
function used by the Claude Code hooks AND by the Aider mirror (`arch-kit edit-check`), so both get identical results.
Every entry point fails open on its own errors and does nothing in a repo without .arch/canon.yaml.
"""

import json
import re
import sys
import time
from pathlib import Path

import arch_check as ck
import arch_config as ac
import arch_lifecycle as lc
import arch_scan as sc

BLOCKING = ("legacy.new-file", "layer.new-to-legacy", "legacy.growth")
PROTECTED = (
    "canon.yaml",
    "exceptions.yaml",
    "baseline.json",
    "decisions.log",
    "pending.json",
)
MAX_WARN_RULES = 3
BASH_WRITE = re.compile(
    r"(>|\btee\b|\bcp\b|\bmv\b|\brm\b|sed\s+-\w*i|\bchmod\b|\btruncate\b|\bpython3?\b|\bperl\b|\bnode\b)"
)
STOP_ATTEMPTS = 3
HEREDOC = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?.*?\n.*?\n\s*\1\b", re.DOTALL)
FD_REDIRECT = re.compile(r"\d*>&\d|\d*>>?\s*/dev/null")
SEGMENT = re.compile(r"&&|\|\||;|\||\n")


def bash_writes_policy(cmd):
    """True when one shell segment both mentions the policy folder and could write to it.
    Heredoc bodies, fd redirects (2>&1, >/dev/null) and read-only git commands do not count."""
    cmd = FD_REDIRECT.sub(" ", HEREDOC.sub(" ", cmd))
    for seg in SEGMENT.split(cmd):
        if f"{ac.ARCH_DIR}/" in seg and BASH_WRITE.search(seg):
            if re.match(
                r"\s*git\s+(add|status|diff|log|show|ls-files|check-ignore|rm\s+--cached)\b",
                seg,
            ):
                continue
            if "arch_kit.py" in seg or "arch-kit" in seg:
                continue
            return True
    return False


def new_content(tool, ti, current):
    if tool == "Write":
        return ti.get("content", "")
    edits = ti.get("edits") if tool == "MultiEdit" else [ti]
    text = current
    for e in edits or []:
        if e.get("old_string") and e["old_string"] in text:
            text = text.replace(
                e["old_string"],
                e.get("new_string", ""),
                1 if not e.get("replace_all") else -1,
            )
    return text


def file_findings(root, canon, rel, text, exists=None):
    """Findings for one file given its (proposed) content. Each: {rule, blocking, line, message}."""
    root = Path(root)
    baseline = ac.load_baseline(root)
    base_counts = baseline.get("violations", {})
    layers = canon.get("layers") or {}
    legacy, new = layers.get("legacy", []), layers.get("new", [])
    exists = (root / rel).is_file() if exists is None else exists
    out = []
    in_legacy = bool(legacy) and ac.matches(rel, legacy)
    lines = text.count("\n") + 1
    if in_legacy and rel.endswith(ac.SOURCE_EXTS):
        sizes = baseline.get("legacy_files", {})
        if rel not in sizes and not exists:
            out.append(
                {
                    "rule": "legacy.new-file",
                    "blocking": True,
                    "line": 1,
                    "message": f"{rel}: new file in a legacy area; put new code in the new layer",
                }
            )
        else:
            ref = sizes.get(rel, ck.line_count(root, rel))
            if lines > ref:
                out.append(
                    {
                        "rule": "legacy.growth",
                        "blocking": True,
                        "line": lines,
                        "message": f"{rel}: legacy file would grow from {ref} to {lines} lines; it may not grow",
                    }
                )
    if (
        legacy
        and not in_legacy
        and (not new or ac.matches(rel, new))
        and rel.endswith(ac.SOURCE_EXTS)
    ):
        fileset = set(ac.list_files(root, canon.get("ignore", [])))
        specs = sc.js_specs(text) if rel.endswith(sc.JS_EXTS) else []
        for spec in specs:
            dst = sc.resolve_js(rel, spec, canon, fileset)
            if (
                dst
                and ac.matches(dst, legacy)
                and base_counts.get(f"layer.new-to-legacy|{rel}|{dst}", 0) == 0
            ):
                out.append(
                    {
                        "rule": "layer.new-to-legacy",
                        "blocking": True,
                        "line": 1,
                        "message": f"{rel}: new import of legacy code {dst}; use or migrate to the new layer",
                    }
                )
        if not rel.endswith(sc.JS_EXTS):
            for level, mod in sc.py_modules(text, rel):
                dst = sc.resolve_py(rel, level, mod, fileset)
                if (
                    dst
                    and ac.matches(dst, legacy)
                    and base_counts.get(f"layer.new-to-legacy|{rel}|{dst}", 0) == 0
                ):
                    out.append(
                        {
                            "rule": "layer.new-to-legacy",
                            "blocking": True,
                            "line": 1,
                            "message": f"{rel}: new import of legacy code {dst}",
                        }
                    )
    for cap, spec in (canon.get("capabilities") or {}).items():
        canonical = spec.get("canonical")
        canonical = [canonical] if isinstance(canonical, str) else (canonical or [])
        if rel in [c.split("#")[0] for c in canonical] or ac.matches(
            rel, spec.get("allow", [])
        ):
            continue
        if spec.get("scope") and not ac.matches(rel, spec["scope"]):
            continue
        for pat in spec.get("bans", []):
            for line_no, line in sc.ban_lines(text, pat):
                key = f"canon.{cap}|{rel}|{pat}|{sc.zlib.crc32(line.strip().encode()):08x}"
                if base_counts.get(key, 0) == 0:
                    hint = (
                        canonical[0].split("#")[0]
                        if canonical
                        else "the canonical module"
                    )
                    out.append(
                        {
                            "rule": f"canon.{cap}",
                            "blocking": False,
                            "line": line_no,
                            "message": f"{rel}:{line_no}: '{pat}' is banned for {cap}; use {hint}",
                        }
                    )
    return out


def pre_edit(payload):
    """Return a denial message or None."""
    tool, ti = payload.get("tool_name", ""), payload.get("tool_input") or {}
    cwd = payload.get("cwd") or "."
    top = ac.git(cwd, "rev-parse", "--show-toplevel").strip()
    if not top:
        return None
    root = Path(top)
    canon = ac.load_canon(root)
    if canon is None:
        return None
    if tool == "Bash":
        cmd = ti.get("command", "")
        if bash_writes_policy(cmd):
            return "the architect's policy files (.arch/) are changed only through arch-kit commands that cite a decision"
        return None
    fp = ti.get("file_path")
    if tool not in ("Edit", "Write", "MultiEdit") or not fp:
        return None
    p = Path(fp)
    try:
        rel = p.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None
    if rel.startswith(ac.ARCH_DIR + "/") and rel.split("/")[-1] in PROTECTED:
        return f"{rel} is policy: change it only with arch-kit commands that cite a decision from the decisions page"
    current = p.read_text(errors="replace") if p.is_file() else ""
    findings = file_findings(
        root, canon, rel, new_content(tool, ti, current), exists=p.is_file()
    )
    blocks = [f["message"] for f in findings if f["blocking"]]
    return "; ".join(blocks) if blocks else None


def post_edit(payload):
    """Warning text for the agent (at most MAX_WARN_RULES distinct rules), or ''."""
    ti = payload.get("tool_input") or {}
    cwd = payload.get("cwd") or "."
    top = ac.git(cwd, "rev-parse", "--show-toplevel").strip()
    fp = ti.get("file_path")
    if not top or not fp:
        return ""
    try:
        rel = Path(fp).resolve().relative_to(Path(top).resolve()).as_posix()
    except ValueError:
        return ""
    text = Path(fp).read_text(errors="replace") if Path(fp).is_file() else ""
    lines = []
    notice = lc.target_notice(top, rel, text)  # works without .arch/canon.yaml
    if notice:
        lines.append(notice)
    canon = ac.load_canon(top)
    seen = set()
    for f in file_findings(top, canon, rel, text, exists=True) if canon else []:
        if f["rule"] not in seen and len(seen) < MAX_WARN_RULES:
            seen.add(f["rule"])
            lines.append("ARCHITECT: " + f["message"])
    return "\n".join(lines)


def edit_check(root, files):
    """The Aider mirror: lint-format lines ('path:line: message') for each file, same findings as the hooks."""
    canon = ac.load_canon(root)
    out, bad = [], 0
    for rel in files:
        p = Path(root) / rel
        text = p.read_text(errors="replace") if p.is_file() else ""
        notice = lc.target_notice(root, rel, text)
        if notice:
            out.append(f"{rel}:1: {notice}")
        for f in file_findings(root, canon, rel, text, exists=True) if canon else []:
            out.append(f"{rel}:{f['line']}: {f['message']}")
            bad += f["blocking"]
    return out, bad


def stop_state(session):
    return (
        Path.home()
        / ".local"
        / "state"
        / "arch-kit"
        / f"stop-{session or 'nosession'}.json"
    )


def stop(payload, budget_s=60):
    """JSON to print (a block decision) or None. At most STOP_ATTEMPTS blocks per session so a stuck check never loops."""
    cwd = payload.get("cwd") or "."
    top = ac.git(cwd, "rev-parse", "--show-toplevel").strip()
    if not top or ac.load_canon(top) is None:
        return None
    added, mod = ac.changed_files(top, ac.base_ref(top))
    if not (added or mod):
        return None
    t0 = time.time()
    res = ck.run_check(top)
    if res["ok"] or time.time() - t0 > budget_s * 4:
        return None
    sp = stop_state(payload.get("session_id"))
    st = ac.load_json(sp, {"n": 0})
    if st["n"] >= STOP_ATTEMPTS:
        return None
    st["n"] += 1
    ac.save_json(sp, st)
    return {
        "decision": "block",
        "reason": ck.format_result(res)
        + "\nFix these (reuse the canonical module, do not add to legacy), or request an exception: arch-kit exception request.",
    }


def main(kind):
    try:
        payload = json.load(sys.stdin)
        if kind == "pre-edit":
            msg = pre_edit(payload)
            if msg:
                sys.stderr.write("ARCHITECT BLOCK: " + msg + "\n")
                return 2
        elif kind == "post-edit":
            out = post_edit(payload)
            if out:
                print(out)
        elif kind == "stop":
            out = stop(payload)
            if out:
                print(json.dumps(out))
        return 0
    except Exception as e:  # noqa: BLE001 - fail open on our own bugs, by design
        sys.stderr.write(f"arch-kit hook error (failing open): {e!r}\n")
        return 0
