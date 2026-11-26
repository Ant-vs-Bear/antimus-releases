"""arch_jobs: repeated jobs found by their numbers and effects, and the per-repository coverage line (SPEC-ARCH-REGISTER-COVERS-THE-JOBS)."""

import re
from collections import defaultdict
from pathlib import Path

import arch_config as ac
import arch_scan as sc

# --- repeated jobs (SPEC-ARCH-REGISTER-COVERS-THE-JOBS): found by their numbers and effects, not by function names ---
WAIT_CONST_RE = re.compile(
    r"^[ \t]*([A-Z][A-Z0-9_]*(?:_S|_SEC|_SECS|_SECONDS|_MINUTES|_WAIT|_DELAY|_AFTER|_INTERVAL))\s*(?::[^=\n]+)?=\s*[\d(]",
    re.MULTILINE,
)
UNIT_WORDS = {
    "S",
    "SEC",
    "SECS",
    "SECONDS",
    "MINUTES",
    "WAIT",
    "DELAY",
    "AFTER",
    "INTERVAL",
    "DEFAULT",
    "MAX",
}
# A system call that is the job: the same effect made from several modules is one job done in several places.
EFFECT_JOBS = {
    "nudge_window": re.compile(r"send-keys|send_keys"),
    "close_window": re.compile(r"kill-window|kill-pane|kill_window"),
    "admit_spec": re.compile(r"admit[-_]spec"),
}
CONST_JOBS = {"NUDGE": "nudge_window", "CLOSE": "close_window", "ADMIT": "admit_spec"}
TEST_FILE_RE = re.compile(
    r"(^|/)(tests?|__tests__)/|(^|/)test_[^/]*$|_test\.\w+$|\.(test|spec)\.\w+$"
)


def _const_job(name):
    words = [w for w in name.split("_") if w and w not in UNIT_WORDS]
    if not words or len(words[0]) < 4:
        return None
    return CONST_JOBS.get(words[0]) or f"{words[0].lower()}_wait"


def repeated_jobs(root, src=None):
    """Clusters of one job done in several files, found by repeated wait constants and repeated system calls.
    Returns [{job, files, constants, effects}] for clusters of 2+ non-test files. Generic function names never count."""
    root = Path(root)
    src = (
        src
        if src is not None
        else [f for f in ac.list_files(root) if f.endswith(ac.SOURCE_EXTS)]
    )
    jobs = defaultdict(lambda: {"files": set(), "constants": set(), "effects": set()})
    for f in src:
        if TEST_FILE_RE.search(f) or ac.matches(f, ac.DEFAULT_DUP_IGNORE):
            continue
        text = sc.read_text(root, f)
        for name in WAIT_CONST_RE.findall(text):
            job = _const_job(name)
            if job:
                jobs[job]["files"].add(f)
                jobs[job]["constants"].add(name)
        for job, rx in EFFECT_JOBS.items():
            if rx.search(text):
                jobs[job]["files"].add(f)
                jobs[job]["effects"].add(rx.pattern)
    return [
        {
            "job": job,
            "files": sorted(v["files"]),
            "constants": sorted(v["constants"]),
            "effects": sorted(v["effects"]),
        }
        for job, v in sorted(jobs.items())
        if len(v["files"]) >= 2
    ]


def coverage(root):
    """One line of numbers per repository: registered jobs, clusters found, clusters still unregistered."""
    root = Path(root)
    canon = ac.load_canon(root) or {}
    registered = set((canon.get("capabilities") or {}).keys())
    clusters = repeated_jobs(root)
    unreg = [c for c in clusters if c["job"] not in registered]
    return {
        "repo": root.name,
        "source_files": len(
            [f for f in ac.list_files(root) if f.endswith(ac.SOURCE_EXTS)]
        ),
        "registered": len(registered),
        "clusters": len(clusters),
        "unregistered": len(unreg),
        "unregistered_jobs": [c["job"] for c in unreg],
        "unregistered_sites": {c["job"]: len(c["files"]) for c in unreg},
    }


def coverage_line(cov):
    tail = ", ".join(
        f"{j} ({cov['unregistered_sites'][j]} sites)" for j in cov["unregistered_jobs"]
    )
    return (
        f"coverage {cov['repo']}: {cov['registered']} registered jobs, {cov['clusters']} repeated-job clusters found, "
        f"{cov['unregistered']} unregistered" + (f": {tail}" if tail else "")
    )
