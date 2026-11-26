#!/usr/bin/env python3
"""Replay `arch-kit move` on a real merged pull request (SPEC-ARCH-PATH-MOVE AP-05).

arch_move_replay.py --repo clickengage --pr 597 [--decision FILE#ID] [--loosen]

Checks out the pull request's head in a throwaway worktree of ~/projects/<repo> (the repo dir may be named differently, see
REPO_DIRS), puts its .arch/decisions.log back to the base version, runs the move against the pull request's base commit, then
runs the policy check. Prints `accepted: yes|no` and `policy check: pass|fail`. With --loosen one rule is also loosened first,
which must be refused.
"""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import arch_check as ck
import arch_config as ac
import arch_move as mv

REPO_DIRS = {"clickengage": "adsvera"}
DEFAULT_DECISIONS = {("clickengage", 597): "rename-internal-cmo-id.decisions.json#d2"}


def run(*cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)


def pr_info(repo, pr):
    r = run(
        "gh",
        "pr",
        "view",
        str(pr),
        "-R",
        f"Ant-vs-Bear/{repo}",
        "--json",
        "baseRefOid,headRefOid",
    )
    if r.returncode:
        raise SystemExit(f"cannot read the pull request: {r.stderr.strip()}")
    d = json.loads(r.stdout)
    return d["baseRefOid"], d["headRefOid"]


def replay(repo, pr, decision, loosen):
    src = Path.home() / "projects" / REPO_DIRS.get(repo, repo)
    base, head = pr_info(repo, pr)
    run("git", "-C", str(src), "fetch", "-q", "origin", f"pull/{pr}/head")
    with tempfile.TemporaryDirectory() as tmp:
        wt = Path(tmp) / "replay"
        if run(
            "git", "-C", str(src), "worktree", "add", "--detach", str(wt), head
        ).returncode:
            raise SystemExit("cannot check out the pull request head")
        try:
            # the window logged the decision by hand; put the log back to what it was at the base
            old_log = run(
                "git", "-C", str(wt), "show", f"{base}:.arch/decisions.log"
            ).stdout
            ac.arch_path(wt, "decisions.log").write_text(old_log)
            if loosen:
                canon = ac.load_canon(wt)
                name = next(iter(canon["capabilities"]))
                canon["capabilities"][name]["bans"] = []
                ac.save_yaml(ac.arch_path(wt, "canon.yaml"), canon)
            try:
                message, _ = mv.record_move(wt, decision, base)
                accepted = True
            except ValueError as error:
                message, accepted = str(error), False
            print(f"accepted: {'yes' if accepted else 'no'}\n{message}")
            if accepted:
                res = ck.check_policy(wt, base)
                print(f"policy check: {'pass' if not res else 'fail'}")
                return 0 if not res else 1
            return 0 if loosen else 1
        finally:
            run("git", "-C", str(src), "worktree", "remove", "--force", str(wt))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--pr", type=int, required=True)
    ap.add_argument("--decision")
    ap.add_argument("--loosen", action="store_true")
    a = ap.parse_args(argv)
    decision = a.decision or DEFAULT_DECISIONS.get((a.repo, a.pr))
    if not decision:
        raise SystemExit("give --decision FILE#ID")
    return replay(a.repo, a.pr, decision, a.loosen)


if __name__ == "__main__":
    sys.exit(main())
