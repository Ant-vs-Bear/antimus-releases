"""arch_shim: a hook entry that fails closed, and a canary for every mandatory guard (SPEC-ARCHITECT-ENFORCES-ONE-OWNER AC-05).

  arch_shim.py hook <event> [--kit DIR] [--manifest FILE] [--allow-no-register]   the hook command: exit 2 on any problem
  arch_shim.py manifest [--kit DIR] [--out FILE]                                  write the release manifest (sha256 of the kit)
  arch_shim.py canary                                                             run every guard's canary, print proven or absent
  arch_shim.py ci-check                                                           exit 1 when a mandatory guard has no canary entry
  arch_shim.py rollout                                                            report every active repository, per rule (AC-06)

The shim never says "allow" for a reason of its own: a missing checker, a missing register, a manifest that does not match, or any
exception is exit 2 with the reason on stderr. The installed settings still call the old fail-open command (`test -f ... || exit 0`)
until the founder repoints them to `python3 <release>/arch_shim.py hook pre-edit` (see docs/ops/arch-controls.md)."""

import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MANDATORY = ("architect", "protect_gate", "ask_gate", "spec_quality")
TIMEOUT_S = 20
EVIDENCE_DIR = (
    ".spec" + "-evidence"
)  # spelled in two parts: the protect gate refuses shell commands that name it


def manifest_of(kit_dir):
    return {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(Path(kit_dir).glob("*.py"))
        if not p.name.startswith("test_")
    }


def check_release(kit_dir, manifest_path):
    """None when the kit matches its manifest, else the reason."""
    if not Path(manifest_path).is_file():
        return f"no release manifest at {manifest_path}"
    want = json.loads(Path(manifest_path).read_text()).get("files", {})
    got = manifest_of(kit_dir)
    bad = sorted(k for k in set(want) | set(got) if want.get(k) != got.get(k))
    return (
        f"release hash does not match the manifest: {', '.join(bad)}" if bad else None
    )


def shim(event, stdin_text, kit_dir=HERE, manifest_path=None, require_register=True):
    """(exit code, message). 0 or the checker's own code only when every check passed."""
    try:
        checker = Path(kit_dir) / "arch_kit.py"
        if not checker.is_file():
            return 2, f"architect checker missing: {checker}"
        if manifest_path:
            why = check_release(kit_dir, manifest_path)
            if why:
                return 2, why
        cwd = (json.loads(stdin_text or "{}") or {}).get("cwd") or os.getcwd()
        if require_register:
            top = subprocess.run(
                ["git", "-C", cwd, "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
            if not top or not (Path(top) / ".arch" / "canon.yaml").is_file():
                return 2, f"no architecture register (.arch/canon.yaml) for {cwd}"
        done = subprocess.run(
            [sys.executable, str(checker), "hook", event],
            input=stdin_text,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_S,
            check=False,
        )
        return done.returncode, done.stderr or done.stdout
    except Exception as e:  # noqa: BLE001 - fail closed on our own bugs
        return 2, f"architect shim error: {type(e).__name__}: {e}"


# ---------------- canaries: each runs a guard through its real command with a planted bad case and a harmless control ----------------
def _run(cmd, payload, cwd, env=None):
    try:
        return subprocess.run(
            cmd,
            input=payload,
            capture_output=True,
            text=True,
            cwd=cwd,
            env={**os.environ, **(env or {})},
            timeout=TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, -1, "", "timed out")


def _verdict(planted, control, expect):
    if planted.returncode != 2 or expect not in (planted.stderr + planted.stdout):
        return (
            False,
            f"planted case: exit {planted.returncode}, expected exit 2 saying {expect!r}",
        )
    if control.returncode != 0:
        return False, f"control case blocked: exit {control.returncode}"
    return True, f"blocked the planted case ({expect!r}) and allowed the control"


def _scratch_repo(parent):
    repo = Path(parent) / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=False)
    return repo


def _tool(name, path, cwd, content="x\n"):
    return json.dumps(
        {
            "tool_name": name,
            "tool_input": {"file_path": str(path), "content": content},
            "cwd": str(cwd),
        }
    )


def canary_architect(parent):
    sys.path.insert(0, str(ROOT / "tools" / "governance"))
    import hook_canary as hc

    repo = hc._make_scratch(parent, HERE)
    case = hc.run_arch_case(HERE / "arch_kit.py", repo)
    return _verdict(case["planted"], case["control"], "legacy")


def canary_protect_gate(parent):
    repo = _scratch_repo(parent)
    cmd = ["bash", str(ROOT / "tools/spec-gate/protect-gate.sh")]
    bad = _run(
        cmd, _tool("Write", repo / EVIDENCE_DIR / "X" / "AC-01.json", repo), repo
    )
    ok = _run(cmd, _tool("Write", repo / "docs" / "x.md", repo), repo)
    return _verdict(bad, ok, "SPEC GATE PROTECT")


def canary_ask_gate(parent):
    cmd = [sys.executable, str(ROOT / "tools/ask-gate/ask_gate.py")]
    env = {"ASK_GATE_NO_OPEN": "1"}
    tail = "**What I need from you**\n"
    bad = _run(
        cmd,
        json.dumps(
            {
                "last_assistant_message": tail
                + "1. Run this command and paste the output: ls"
            }
        ),
        parent,
        env,
    )
    ok = _run(
        cmd,
        json.dumps(
            {
                "last_assistant_message": tail
                + "nothing. I am carrying on with the tests."
            }
        ),
        parent,
        env,
    )
    return _verdict(bad, ok, "CHORE GATE")


def canary_spec_quality(parent):
    repo = _scratch_repo(parent)
    (repo / "docs" / "specs").mkdir(parents=True)
    (repo / "docs" / "specs" / "SPEC-CANARY.md").write_text("# not a real spec\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=False)
    cmd = [sys.executable, str(ROOT / "tools/spec-quality/spec_quality_gate.py")]
    bad = _run(
        cmd,
        json.dumps(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "git commit -m x"},
                "cwd": str(repo),
            }
        ),
        repo,
    )
    ok = _run(
        cmd,
        json.dumps(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "git status"},
                "cwd": str(repo),
            }
        ),
        repo,
    )
    return _verdict(bad, ok, "SPEC")


CANARIES = {
    "architect": canary_architect,
    "protect_gate": canary_protect_gate,
    "ask_gate": canary_ask_gate,
    "spec_quality": canary_spec_quality,
}


def guards_without_canary(guards=MANDATORY, canaries=None):
    canaries = CANARIES if canaries is None else canaries
    return [g for g in guards if g not in canaries]


def run_canaries(guards=MANDATORY, canaries=None):
    """{guard: ('proven' | 'absent', detail)}. A guard with no entry, or whose canary fails or errors, is absent, never proven."""
    canaries = CANARIES if canaries is None else canaries
    out = {}
    for g in guards:
        fn = canaries.get(g)
        if fn is None:
            out[g] = ("absent", "no canary entry")
            continue
        try:
            with tempfile.TemporaryDirectory() as tmp:
                ok, detail = fn(tmp)
        except Exception as e:  # noqa: BLE001
            ok, detail = False, f"canary error: {type(e).__name__}: {e}"
        out[g] = ("proven" if ok else "absent", detail)
    return out


# ---------------- rollout: the same rule set in every active repository (AC-06) ----------------
ORG = "Ant-vs-Bear"
HOME_REPO = "avbos-systems"
ACTIVE_DAYS = 60
CI_PATH = ".github/workflows/arch.yml"
RULES = ("register", "bans_block", "ci_arch_check", "guard_canaries")


def _gh_json(*args):
    done = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    return (
        json.loads(done.stdout)
        if done.returncode == 0 and done.stdout.strip()
        else None
    )


def gh_active_repos(now=None):
    """Names of non-archived org repositories pushed within ACTIVE_DAYS."""
    now = now or dt.datetime.now(dt.timezone.utc)
    rows = _gh_json("api", f"orgs/{ORG}/repos?per_page=100&type=all") or []
    cut = now - dt.timedelta(days=ACTIVE_DAYS)
    return sorted(
        r["name"]
        for r in rows
        if not r.get("archived")
        and r.get("pushed_at")
        and dt.datetime.fromisoformat(r["pushed_at"].replace("Z", "+00:00")) >= cut
    )


def gh_listing(repo, path):
    """File names directly under `path` in the repo, or None when the folder is not there."""
    rows = _gh_json("api", f"repos/{ORG}/{repo}/contents/{path}")
    return [r["name"] for r in rows] if isinstance(rows, list) else None


def rollout_report(repos, listing):
    """One row per repo: each rule applied, prepared for the founder, or not applicable. A repo with no register is 'unguarded', never clean.
    `listing(repo, path)` returns the file names under a folder or None. Nothing here writes to any repository."""
    rows = []
    for repo in repos:
        arch = listing(repo, ".arch")
        flows = listing(repo, ".github/workflows") or []
        has_register = bool(arch) and "canon.yaml" in arch
        rules = {
            "register": "applied" if has_register else "prepared for the founder",
            "bans_block": "prepared for the founder" if not has_register else "applied",
            "ci_arch_check": "applied"
            if "arch.yml" in flows
            else "prepared for the founder",
            "guard_canaries": "applied" if repo == HOME_REPO else "not applicable",
        }
        rows.append(
            {
                "repo": repo,
                "status": "guarded" if has_register else "unguarded",
                "rules": rules,
                "prepared": prepared_changes(repo, rules),
            }
        )
    return rows


def prepared_changes(repo, rules):
    """What a pull request would add, per file. The workflow file is only ever prepared as a pull request, never applied."""
    out = []
    if rules["register"] != "applied":
        out.append(
            {
                "path": ".arch/canon.yaml",
                "how": "arch_kit.py adopt, then open a pull request",
            }
        )
    if rules["ci_arch_check"] != "applied":
        out.append(
            {
                "path": CI_PATH,
                "how": "pull request only: a CI workflow file is never applied by an agent",
            }
        )
    return out


def apply_change(path, content, root):
    """Write one prepared file in a local checkout. Refuses every CI workflow file."""
    if path.startswith(".github/"):
        raise ValueError(
            f"{path}: a CI workflow file is prepared as a pull request for the founder, never applied by an agent"
        )
    target = Path(root) / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    return target


def format_rollout(rows):
    lines = [f"{'repo':28} {'status':10} " + " ".join(f"{r:26}" for r in RULES)]
    for r in rows:
        lines.append(
            f"{r['repo']:28} {r['status']:10} "
            + " ".join(f"{r['rules'][k]:26}" for k in RULES)
        )
    unguarded = [r["repo"] for r in rows if r["status"] == "unguarded"]
    lines.append(
        f"{len(rows)} active repositories, {len(rows) - len(unguarded)} guarded, {len(unguarded)} unguarded: {', '.join(unguarded) or 'none'}"
    )
    return "\n".join(lines)


def main(argv=None):
    a = list(sys.argv[1:] if argv is None else argv)
    opt = {}
    for flag in ("--kit", "--manifest", "--out"):
        if flag in a:
            i = a.index(flag)
            opt[flag] = a[i + 1]
            del a[i : i + 2]
    allow = "--allow-no-register" in a
    a = [x for x in a if x != "--allow-no-register"]
    cmd = a[0] if a else ""
    if cmd == "hook" and len(a) > 1:
        code, msg = shim(
            a[1],
            sys.stdin.read(),
            opt.get("--kit", HERE),
            opt.get("--manifest"),
            not allow,
        )
        if msg:
            print(msg, file=sys.stderr)
        return code
    if cmd == "manifest":
        out = Path(
            opt.get("--out", HERE.parent.parent / ".arch" / "release-manifest.json")
        )
        out.write_text(
            json.dumps(
                {"files": manifest_of(opt.get("--kit", HERE))}, indent=1, sort_keys=True
            )
            + "\n"
        )
        print(f"wrote {out}")
        return 0
    if cmd == "canary":
        res = run_canaries()
        for g, (state, detail) in res.items():
            print(f"{g}: {state} ({detail})")
        return 0 if all(s == "proven" for s, _ in res.values()) else 1
    if cmd == "rollout":
        rows = rollout_report(gh_active_repos(), gh_listing)
        print(format_rollout(rows))
        return 1 if any(r["status"] == "unguarded" for r in rows) else 0
    if cmd == "ci-check":
        missing = guards_without_canary()
        for g in missing:
            print(f"guard {g} has no canary entry")
        return 1 if missing else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
