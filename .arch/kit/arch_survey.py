"""arch_survey: read-only survey of a repo, draft policy, founder cards, and adoption (SPEC-CHIEF-ARCHITECT section 5.9).

`survey` never writes into the repo. Every finding is classified: observed (measured), inferred (heuristic) or unresolved
(needs the founder). Names alone never create a rule. `adopt` writes the policy files, baseline, generated docs, a vendored
copy of the kit for CI, and a CI workflow when none exists; it is idempotent.
"""

import json
import re
import shutil
import time
from collections import Counter, defaultdict
from pathlib import Path

import arch_check as ck
import arch_config as ac
import arch_gen
import arch_scan as sc
from arch_jobs import coverage, coverage_line, repeated_jobs  # noqa: F401

TOOLS = Path(__file__).resolve().parent
MAX_CARDS = 10
LEGACY_DIR_NAMES = {"legacy", "old", "deprecated", "v1"}
INTERESTING = re.compile(
    r"(format|escape|parse|timezone|tz|date|money|price|currency|client|http|request|config|validate|sanitize)",
    re.IGNORECASE,
)
# Only exported functions (TS/JS) and top-level defs (Python) count as shared jobs; local variables never do.
DEF_RE = re.compile(
    r"^(?:export\s+(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_]\w*)"
    r"|export\s+const\s+([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_]\w*)\s*(?:=>|:)"
    r"|(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\()",
    re.MULTILINE,
)
SKIP_NAMES = {
    "default",
    "main",
    "handler",
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "render",
    "setup",
    "init",
    "test",
    "get",
    "set",
}
STACK_DEFAULTS = {
    "nextjs": {"aliases": {"@/": ["src/", ""]}, "loose": {"flat_dirs": ["src/lib"]}},
    "react-native": {"aliases": {"@/": [""]}, "loose": {"flat_dirs": []}},
    "node-api": {"aliases": {}, "loose": {"flat_dirs": []}},
    "python": {"aliases": {}, "loose": {"flat_dirs": []}},
}


def detect_stack(root):
    pj = ac.load_json(Path(root) / "package.json", {})
    deps = {**pj.get("dependencies", {}), **pj.get("devDependencies", {})}
    if "next" in deps:
        return "nextjs"
    if "expo" in deps or "react-native" in deps:
        return "react-native"
    if pj:
        return "node-api"
    return "python"


def last_commit_age_days(root, d):
    ts = ac.git(root, "log", "-1", "--format=%ct", "--", d).strip()
    return (time.time() - int(ts)) / 86400 if ts.isdigit() else None


NOT_CODE_DIRS = {
    "app",
    "pages",
    "scripts",
    "tests",
    "test",
    "e2e",
    "docs",
    "public",
    "assets",
    "tools",
    "types",
    "config",
    "supabase",
}


def quiet_folders(root, tops, src):
    """Top-level folders (10+ source files) with under a tenth of the busiest folder's commits in the last 60 days."""
    log = ac.git(root, "log", "--since=60.days", "--name-only", "--format=")
    activity = Counter(p.split("/")[0] for p in log.splitlines() if "/" in p)
    cands = [d for d in tops if d not in NOT_CODE_DIRS]
    if len(cands) < 3 or not activity:
        return []
    busiest = max(cands, key=lambda d: activity.get(d, 0))
    size = Counter(f.split("/")[0] for f in src)
    return sorted(
        d
        for d in cands
        if d != busiest
        and size[d] >= 10
        and activity.get(d, 0) * 10 <= activity.get(busiest, 0)
    )


def survey(root):
    """Read-only. Returns a dict with findings (each classified) and a draft canon."""
    root = Path(root)
    stack = detect_stack(root)
    draft = {
        "version": 1,
        "stack": stack,
        "roots": [],
        "ignore": [],
        **{k: v for k, v in STACK_DEFAULTS[stack].items()},
        "capabilities": {},
        "layers": {},
        "enforce": list(ac.DEFAULT_ENFORCE),
    }
    draft["dup"] = {"min_tokens": 60, "ignore_names": list(ac.DEFAULT_DUP_IGNORE)}
    files = ac.list_files(root)
    canon = {**draft, "dup": draft["dup"]}
    src = [f for f in files if f.endswith(ac.SOURCE_EXTS)]
    e = sc.edges(root, src, canon)
    indeg = Counter(dst for _, dst in e)
    findings = []
    # duplicated names that look like shared jobs
    defs = defaultdict(set)
    for f in src:
        if ac.matches(f, ac.DEFAULT_DUP_IGNORE):
            continue
        for name in (n for m in DEF_RE.findall(sc.read_text(root, f)) for n in m if n):
            if INTERESTING.search(name) and name not in SKIP_NAMES:
                defs[name].add(f)
    for name, fs in sorted(defs.items()):
        if len(fs) >= 2:
            findings.append(
                {
                    "kind": "same-name",
                    "class": "observed",
                    "name": name,
                    "files": sorted(fs),
                    "most_imported": max(sorted(fs), key=lambda x: indeg.get(x, 0)),
                    "note": "same function name in several files; behaviour may differ (verify before merging)",
                }
            )
    # raw fetch / axios spread
    fetch_files = sorted(f for f in src if "fetch(" in sc.read_text(root, f))
    if len(fetch_files) >= 4:
        findings.append(
            {
                "kind": "http-spread",
                "class": "inferred",
                "name": "raw fetch(",
                "files": fetch_files,
                "note": "raw fetch in many files; whether one client is right depends on the runtime (server, browser, external)",
            }
        )
    for c in repeated_jobs(root, src):
        findings.append(
            {
                "kind": "repeated-job",
                "class": "observed",
                "name": c["job"],
                "files": c["files"],
                "constants": c["constants"],
                "note": "the same job (wait numbers or system calls) appears in several files; accept by naming the one module",
            }
        )
    cl = sc.clones(root, src, canon)
    findings.append(
        {
            "kind": "copy-paste",
            "class": "observed",
            "count": len(cl),
            "pairs": [[c["path"], c["target"]] for c in cl[:20]],
            "note": "identical code blocks (route/page/test files already ignored)",
        }
    )
    loose = sc.loose_violations(files, canon)
    if loose:
        findings.append(
            {
                "kind": "loose",
                "class": "observed",
                "files": [v["path"] for v in loose],
                "note": "documents at the repo root or loose files",
            }
        )
    tops = sorted({f.split("/")[0] for f in src if "/" in f})
    ages = {d: last_commit_age_days(root, d) for d in tops}
    active = [a for a in ages.values() if a is not None and a < 60]
    old = sorted(d for d, a in ages.items() if a is not None and a > 120 and active)
    named = sorted(d for d in tops if d.lower() in LEGACY_DIR_NAMES)
    quiet = [] if (old or named) else quiet_folders(root, tops, src)
    if old or named or quiet:
        findings.append(
            {
                "kind": "legacy-candidates",
                "class": "inferred" if (old or named) else "unresolved",
                "dirs": sorted(set(old) | set(named) | set(quiet)),
                "note": "folders untouched for months while others are active, or named legacy; confirm with the founder"
                if (old or named)
                else "folders that get almost none of the recent commits while one folder gets most; only the founder knows if they are the old generation",
            }
        )
    cross = [(s, d) for s, d in e if s.split("/")[0] != d.split("/")[0]]
    return {
        "stack": stack,
        "files": len(files),
        "source_files": len(src),
        "import_edges": len(e),
        "cross_folder_edges": len(cross),
        "findings": findings,
        "draft_canon": draft,
        "generated": time.strftime("%Y-%m-%d"),
    }


def cards(sv):
    """At most MAX_CARDS binary or ternary decisions in the decisions-page schema, with evidence and a recommended answer."""
    out = []
    for f in sv["findings"]:
        if len(out) >= MAX_CARDS - 1:
            break
        if f["kind"] == "same-name":
            opts = [
                {
                    "id": chr(97 + i),
                    "label": f"Use {p}"
                    + (" (most used)" if p == f["most_imported"] else ""),
                    "consequence": "This becomes the one place for this job; others are replaced over time, with tests first.",
                    "recommended": p == f["most_imported"],
                }
                for i, p in enumerate(f["files"][:3])
            ]
            opts += [
                {
                    "id": "n",
                    "label": "They are different jobs: no rule",
                    "consequence": "No rule is created; the names stay separate.",
                },
                {"id": "other", "label": "Other"},
            ]
            out.append(
                {
                    "id": f"c{len(out) + 1}",
                    "kind": "question",
                    "impact": "med",
                    "title": f"Which one is the right '{f['name']}'?",
                    "plain_english": f"'{f['name']}' is defined in {len(f['files'])} files. If they do the same job there should be one; if they do different jobs they should have different names.",
                    "why_it_matters": "Two versions of the same job drift apart and one of them eventually produces a wrong answer.",
                    "evidence": f"{f['class']}: " + ", ".join(f["files"][:5]),
                    "if_unsure": "Pick the most used one; the survey recommends it.",
                    "reversible": "Yes. It is a policy entry and can be changed later.",
                    "options": opts,
                }
            )
        elif f["kind"] == "legacy-candidates":
            out.append(
                {
                    "id": f"c{len(out) + 1}",
                    "kind": "question",
                    "impact": "high",
                    "requires_explicit_choice": True,
                    "title": "Are these the old code areas?",
                    "plain_english": "These folders look like an older generation of code: "
                    + ", ".join(f["dirs"])
                    + ". If you confirm, they are frozen: no new files, no growth, and new code may not depend on them.",
                    "why_it_matters": "Without a fence, new code keeps leaning on old code and the old code never goes away.",
                    "evidence": f"{f['class']}: " + f["note"],
                    "if_unsure": "Confirm them; the freeze only stops growth, it changes no behaviour.",
                    "reversible": "Yes. Folders can be removed from the list at any time.",
                    "options": [
                        {
                            "id": "a",
                            "label": "Yes, freeze these",
                            "consequence": "They may not grow and new code may not import them.",
                            "recommended": True,
                        },
                        {
                            "id": "b",
                            "label": "No, they are current code",
                            "consequence": "No fence; nothing changes.",
                        },
                        {"id": "other", "label": "Other"},
                    ],
                }
            )
    out.append(
        {
            "id": f"c{len(out) + 1}",
            "kind": "question",
            "impact": "high",
            "requires_explicit_choice": True,
            "title": "Adopt the Chief Architect on this product?",
            "plain_english": f"This records how this {sv['stack']} product is organised today and then stops it getting worse: existing problems are written down and allowed, new duplicates, new dependence on old code and growth of old files are not. At first it only stops three clear-cut things and warns about the rest.",
            "why_it_matters": "Without it nothing stops the next feature adding another copy of something that already exists.",
            "evidence": f"survey of {sv['source_files']} source files, {sv['import_edges']} imports, {len(sv['findings'])} finding group(s)",
            "if_unsure": "Adopt: it changes no behaviour, only adds the policy files, a check and a small CI workflow, and is removable.",
            "reversible": "Yes. Delete the .arch folder and the workflow to remove it.",
            "options": [
                {
                    "id": "a",
                    "label": "Adopt with the proposed starting policy",
                    "consequence": "Policy, baseline, generated architecture doc and CI check are added in one pull request.",
                    "recommended": True,
                },
                {
                    "id": "b",
                    "label": "Not yet",
                    "consequence": "Nothing is added; the survey can be run again later.",
                },
                {"id": "other", "label": "Other"},
            ],
        }
    )
    return out


def write_cards(root, sv):
    cs = cards(sv)
    name = f"arch-survey-{Path(root).name}.decisions.json"
    data = {
        "title": f"Architecture survey: {Path(root).name}",
        "status": "pending",
        "budget": max(5, len(cs)),
        "context": f"Survey of {Path(root).name} ({sv['stack']}).",
        "basis_unstated": True,
        "scope": {
            "will_build": "A written, checkable architecture policy for this product.",
            "wont_build": "Any code changes or refactors.",
            "done_when": "Each card below is answered.",
        },
        "decisions": cs,
    }
    ac.decisions_dir().mkdir(parents=True, exist_ok=True)
    p = ac.decisions_dir() / name
    ac.save_json(p, data)
    return p, len(cs)


def bans_for(name, canonical):
    """Ban patterns that match how `name` is declared in the canonical file's language. A Python helper is `def name(`, which the old
    JavaScript-only patterns (`function name`, `const name =`) never matched, so a second copy in a Python repo passed the check."""
    if str(canonical).endswith(".py"):
        return [rf"re:^\s*(async\s+)?def {name}\(", rf"re:^{name}\s*="]
    return [f"function {name}", f"const {name} ="]


def apply_answers(draft, sv, decisions_file=None):
    """Fold the founder's card answers (if any) into the draft policy. Unanswered cards add no rule.
    The note on an 'Other' answer to the legacy card is read as the list of old folders."""
    canon = json.loads(json.dumps(draft))
    answers = {}
    if decisions_file:
        data = ac.load_json(decisions_file, {})
        answers = {
            d["id"]: (d.get("answer"), d.get("note") or "")
            for d in data.get("decisions", [])
            if d.get("answer")
        }
    cs = {c["id"]: c for c in cards(sv)}
    for cid, (ans, note) in answers.items():
        c = cs.get(cid)
        if not c:
            continue
        if c["title"].startswith("Are these") and ans in ("a", "other"):
            dirs = next(
                f["dirs"] for f in sv["findings"] if f["kind"] == "legacy-candidates"
            )
            if ans == "other":
                dirs = [
                    d.strip("/ ") for d in re.split(r"[,\s]+", note) if d.strip("/ ")
                ]
            canon["layers"]["legacy"] = [d + "/**" for d in dirs]
            canon["layers"].setdefault("new", [])
        elif c["title"].startswith("Which one") and ans not in ("n", "other"):
            name = re.search(r"'(\w+)'", c["title"]).group(1)
            f = next(
                f
                for f in sv["findings"]
                if f["kind"] == "same-name" and f["name"] == name
            )
            canonical = f["files"][ord(ans) - 97]
            canon["capabilities"][name] = {
                "canonical": canonical,
                "bans": bans_for(name, canonical),
                "allow": [],
                "note": "chosen from the survey",
            }
        elif c["title"].startswith("Adopt the Chief") and ans == "b":
            canon["_declined"] = True
    return canon


def adopt(root, decisions_file=None):
    """Write policy, baseline, generated docs, vendored kit and CI. Idempotent. Returns the list of files written."""
    root = Path(root)
    sv = survey(root)
    canon = (
        apply_answers(sv["draft_canon"], sv, decisions_file)
        if not ac.arch_path(root, "canon.yaml").is_file()
        else ac.load_canon(root)
    )
    if canon.pop("_declined", False):
        return []  # the founder answered "Not yet"
    written = []
    if not ac.arch_path(root, "canon.yaml").is_file():
        ac.save_yaml(ac.arch_path(root, "canon.yaml"), canon)
        written.append(".arch/canon.yaml")
        written += log_adoption(root, decisions_file)
    canon = ac.load_canon(root)
    if not ac.arch_path(root, "baseline.json").is_file():
        ac.save_baseline(
            ac.arch_path(root, "baseline.json"), ck.build_baseline(root, canon)
        )
        written.append(".arch/baseline.json")
    if not ac.arch_path(root, "exceptions.yaml").is_file():
        ac.save_yaml(ac.arch_path(root, "exceptions.yaml"), {"exceptions": []})
        written.append(".arch/exceptions.yaml")
    written += arch_gen.gen(root)
    written += vendor_kit(root)
    written += ensure_arch_gitignore(root)
    written += ensure_ci(root, canon)
    written += ensure_pointers(root)
    return written


def log_adoption(root, decisions_file):
    """Record the founder's 'adopt' answer in .arch/decisions.log so the policy check can tie the new policy files to it."""
    if not decisions_file:
        return []
    data = ac.load_json(decisions_file, {})
    card = next(
        (
            d
            for d in data.get("decisions", [])
            if d.get("title", "").startswith("Adopt the Chief") and d.get("answer")
        ),
        None,
    )
    if not card:
        return []
    log = ac.arch_path(root, "decisions.log")
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, "a") as f:
        f.write(f"{ac.today().isoformat()} {Path(decisions_file).name}#{card['id']}\n")
    return [".arch/decisions.log"]


def ensure_arch_gitignore(root):
    """Keep caches out of the repo and make sure a repo-wide `*.log` ignore cannot hide decisions.log."""
    gi = ac.arch_path(root, ".gitignore")
    want = "__pycache__/\n*.pyc\n!decisions.log\n"
    if gi.is_file() and gi.read_text() == want:
        return []
    gi.write_text(want)
    return [".arch/.gitignore"]


def vendor_kit(root):
    """A pinned copy of the kit inside the repo so CI needs no access to the founder's machine."""
    dst = ac.arch_path(root, "kit")
    dst.mkdir(parents=True, exist_ok=True)
    written = []
    for src in sorted(TOOLS.glob("arch_*.py")):
        if src.name.startswith("test_"):
            continue
        d = dst / src.name
        if not d.is_file() or d.read_bytes() != src.read_bytes():
            shutil.copy2(src, d)
            written.append(f".arch/kit/{src.name}")
    return written


def ensure_ci(root, canon):
    wf = Path(root) / ".github" / "workflows" / "arch.yml"
    if wf.is_file():
        return []
    wf.parent.mkdir(parents=True, exist_ok=True)
    tpl = (
        TOOLS
        / "templates"
        / ("ci-python.yml" if canon.get("stack") == "python" else "ci-node.yml")
    )
    (wf.parent / "arch.yml").write_text(tpl.read_text())
    return [".github/workflows/arch.yml"]


def ensure_pointers(root):
    written = []
    claude = Path(root) / "CLAUDE.md"
    line = "\n## Architecture\nThe one way to do each job is in `.arch/canon.yaml`; the layout is in `docs/ARCHITECTURE.md`. Check before adding anything new: `python3 .arch/kit/arch_kit.py check`.\n"
    if not claude.is_file() or "canon.yaml" not in claude.read_text():
        claude.write_text(
            (claude.read_text() if claude.is_file() else "# CLAUDE.md\n") + line
        )
        written.append("CLAUDE.md")
    aider = Path(root) / ".aider.conf.yml"
    if not aider.is_file():
        aider.write_text(
            'read:\n  - docs/ARCHITECTURE.md\n  - .arch/canon.yaml\nlint-cmd: "python3 .arch/kit/arch_kit.py edit-check"\n'
            'test-cmd: "python3 .arch/kit/arch_kit.py check"\nauto-lint: true\n'
        )
        written.append(".aider.conf.yml")
    return written
