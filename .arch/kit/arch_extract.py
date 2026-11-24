"""arch_extract: the org-wide duplicate extraction: every active repository's honest verdict, scanned in parallel
(SPEC-ARCH-CHECK-FINDS-DUPLICATES-ON-ITS-OWN)."""

import warnings
from pathlib import Path

from arch_blind import WORKERS, active_repos, gap, verdict

warnings.filterwarnings(
    "ignore", category=SyntaxWarning
)  # scanned repositories carry their own bad escapes


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


def _scan(job):
    """One repository's verdict lines and whether it failed; module level so a worker process can run it."""
    import arch_check

    name, here = job
    lines = []
    try:
        failed = extract_one(arch_check.repo_path(name, here), lines.append) != 0
    except (RuntimeError, OSError, ValueError) as e:  # reported, never called clean
        lines.append(f"{name}: could not be scanned ({e})")
        failed = True
    return lines, failed


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
    from concurrent.futures import ProcessPoolExecutor

    bad = len(gaps)
    with ProcessPoolExecutor(
        WORKERS
    ) as pool:  # the extraction is CPU work: processes, order kept
        for lines, failed in pool.map(_scan, [(n, str(here)) for n in names]):
            for line in lines:
                out(line)
            bad += failed
    return 1 if bad else 0
