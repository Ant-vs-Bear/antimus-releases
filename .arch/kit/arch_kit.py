#!/usr/bin/env python3
"""arch-kit: the chief architect (SPEC-CHIEF-ARCHITECT).

arch_kit.py survey [--cards]                    read-only survey, draft policy and founder cards
arch_kit.py adopt [--answers FILE]              write .arch/ policy, baseline, generated docs, vendored kit, CI
arch_kit.py gen                                 regenerate docs/ARCHITECTURE.md block and derived configs
arch_kit.py capability add NAME --canonical P --ban X [--allow G] [--note T] --decision FILE#ID   widen the rulebook (needs a resolved decision)
arch_kit.py move --decision FILE#ID [--base REF]   record a pure path move (rename only) citing a resolved decision
arch_kit.py check [--touched] [--places] [--policy] [--strict] [--base REF] [--json]
arch_kit.py ratchet                             shrink the baseline to what still exists (never adds)
arch_kit.py tighten --rule R [--rule R2] --decision FILE#ID   make rules blocking, baseline today's hits (needs a resolved decision)
arch_kit.py plan "<feature>" [--nouns a,b] [--validate] [--card] [--force]   plan-time stage
arch_kit.py spec-block <spec.md>                append the standard ARCH block to a spec
arch_kit.py exception request --rule R --scope S --reason T | resolve
arch_kit.py digest [--card]                     weekly numbers
arch_kit.py edit-check FILE...                  Aider mirror: lint-format findings, same as the hooks
arch_kit.py hook pre-edit|post-edit|stop        Claude Code hook entry points
arch_kit.py lifecycle check [--base REF] [--json] | gen   superseded-code records (SPEC-SUPERSESSION)
"""

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import arch_capability as cap
import arch_check as ck
import arch_config as ac
import arch_digest as dg
import arch_exceptions as ax
import arch_gen
import arch_hooks as hk
import arch_lifecycle as lc
import arch_move as mv
import arch_plan as pl
import arch_survey as sv

VERSION = "1.0"


def find_root(arg=None):
    top = ac.git(arg or ".", "rev-parse", "--show-toplevel").strip()
    return Path(top) if top else Path(arg or ".").resolve()


def build_parser():
    ap = argparse.ArgumentParser(prog="arch-kit")
    ap.add_argument("--root")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("survey")
    s.add_argument("--cards", action="store_true")
    a = sub.add_parser("adopt")
    a.add_argument("--answers")
    sub.add_parser("gen")
    c = sub.add_parser("check")
    for f in ("--touched", "--places", "--policy", "--strict", "--json"):
        c.add_argument(f, action="store_true")
    c.add_argument("--base")
    sub.add_parser("ratchet")
    t = sub.add_parser("tighten")
    t.add_argument("--rule", action="append", required=True)
    t.add_argument("--decision", required=True)
    p = sub.add_parser("plan")
    p.add_argument("feature", nargs="?", default="")
    p.add_argument("--nouns", default="")
    p.add_argument("--validate", action="store_true")
    p.add_argument("--card", action="store_true")
    p.add_argument("--force", action="store_true")
    sb = sub.add_parser("spec-block")
    sb.add_argument("spec")
    cp = sub.add_parser("capability")
    cp.add_argument("action", choices=["add", "symptoms"])
    cp.add_argument("name")
    cp.add_argument("--canonical")
    cp.add_argument("--symptom", action="append", default=[])
    cp.add_argument("--ban", action="append", default=[])
    cp.add_argument("--allow", action="append", default=[])
    cp.add_argument("--note", default="")
    cp.add_argument("--decision", required=True)
    mvp = sub.add_parser("move")
    mvp.add_argument("--decision", required=True)
    mvp.add_argument("--base")
    e = sub.add_parser("exception")
    e.add_argument("action", choices=["request", "resolve"])
    e.add_argument("--rule")
    e.add_argument("--scope")
    e.add_argument("--reason")
    d = sub.add_parser("digest")
    d.add_argument("--card", action="store_true")
    d.add_argument("--all", action="store_true")
    ec = sub.add_parser("edit-check")
    ec.add_argument("files", nargs="+")
    h = sub.add_parser("hook")
    h.add_argument("kind", choices=["pre-edit", "post-edit", "stop"])
    lf = sub.add_parser("lifecycle")
    lf.add_argument("action", choices=["check", "gen"])
    lf.add_argument("--base")
    lf.add_argument("--json", action="store_true")
    sub.add_parser("version")
    return ap


def cmd_check(root, a):
    res = ck.run_check(
        root,
        touched=a.touched,
        base=a.base,
        places=a.places,
        policy=a.policy,
        strict=a.strict,
    )
    res = repair_check(root, res, a.base, quiet=a.json)
    print(json.dumps(res, indent=1) if a.json else ck.format_result(res))
    return 0 if res["ok"] else 1


def branch_spec(root, base):
    """The one spec named in the branch's commit messages, read from base else HEAD."""
    log = ac.git(root, "log", "--format=%B", f"{base}..HEAD")
    names = []
    for m in re.finditer(ck.SPEC_NAME_RE, log):
        name = m.group(1) if m.groups() else m.group(0)
        if name not in names:
            names.append(name)
    for p in sorted((Path(root) / "docs/specs").glob("*.md")):
        if p.stem in log and p.stem not in names:
            names.append(p.stem)
    for name in names:
        rel = f"docs/specs/{name}.md"
        text = ac.git(root, "show", f"{base}:{rel}")
        if not text.strip():
            text = ac.git(root, "show", f"HEAD:{rel}")
        if not text.strip():
            p = Path(root) / rel
            text = p.read_text() if p.exists() else ""
        if text.strip():
            return name, text
    return (names[0] if names else None), ""


def branch_lines(root, base):
    """Lines added and removed over the branch, ignoring docs, evidence and tests."""
    added = removed = 0
    for line in ac.git(root, "diff", "--numstat", f"{base}...HEAD").splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        a, r, path = parts
        if path.startswith("docs/") or "spec-evidence" in path:
            continue
        if Path(path).name.startswith("test_"):
            continue
        added += int(a) if a.isdigit() else 0
        removed += int(r) if r.isdigit() else 0
    return added, removed


def spec_budget(text):
    """The number of lines a spec's Budget line allows, or None."""
    m = re.search(r"^Budget:.*?(\d+)\s+lines", text, re.MULTILINE)
    return int(m.group(1)) if m else None


def spec_retires(text):
    """The registered capability names a spec's Retires line lists."""
    m = re.search(r"^Retires:\s*(.+)$", text, re.MULTILINE)
    return [n.strip() for n in m.group(1).split(",") if n.strip()] if m else []


def repair_check(root, res, base, quiet=False):
    """RP-03: a repair spec must name what it retires and stay inside its budget."""
    if not base:
        return res
    added, removed = branch_lines(root, base)
    if not quiet:
        print(f"net lines: +{added} -{removed} = {added - removed}")
    name, text = branch_spec(root, base)
    if not text:
        return res
    retired = spec_retires(text)
    kept = []
    for v in res.get("failing", []):
        hit = next((n for n in retired if v.get("rule") == f"canon.{n}"), None)
        if hit:
            if not quiet:
                print(f"retired by spec: {hit}")
            continue
        kept.append(v)
    res["failing"] = kept
    budget = spec_budget(text)
    if budget is not None and added > budget and "Over budget because:" not in text:
        res["failing"].append(
            {
                "rule": "repair.budget",
                "path": f"docs/specs/{name}.md",
                "target": "",
                "detail": f"budget {budget} lines, added {added}",
            }
        )
    res["ok"] = not res["failing"]
    return res


def cmd_plan(root, a):
    canon = ac.load_canon(root)
    if canon is None:
        print("no .arch/canon.yaml: run arch-kit adopt first")
        return 1
    if a.validate:
        errs, needs = pl.validate(root)
        print(
            "\n".join(errs)
            if errs
            else "plan OK" + (" (a founder card is needed)" if needs else "")
        )
        if a.card and not errs and needs:
            print(
                "card:",
                pl.founder_card(root, ac.load_json(ac.arch_path(root, "plan.json"))),
            )
        return 1 if errs else 0
    path, wrote = pl.write_plan(
        root, canon, a.feature, [n for n in a.nouns.split(",") if n], a.force
    )
    print(
        ("wrote " if wrote else "kept existing ")
        + str(path)
        + "\nOpen the candidate modules, then fill place, reuse, new_shared_modules, touches_legacy, exceptions_needed; then: arch-kit plan --validate"
    )
    return 0


def cmd_digest(root, a):
    roots = (
        [
            p.parent.parent
            for p in sorted((Path.home() / "projects").glob("*/.arch/canon.yaml"))
        ]
        if a.all
        else [root]
    )
    for r in roots:
        hist = dg.record(r)
        print(f"== {r.name}\n" + dg.table(hist))
        if a.card:
            print("card:", dg.digest_card(r, hist))


def cmd_capability(root, a):
    try:
        written = (
            cap.set_symptoms(root, a.name, a.symptom, a.decision)
            if a.action == "symptoms"
            else cap.add_capability(
                root, a.name, a.canonical, a.ban, a.allow, a.note, a.decision
            )
        )
    except ValueError as error:
        print(f"refused: {error}")
        return 1
    print("\n".join(written))
    return 0


def main(argv=None):
    a = build_parser().parse_args(argv)
    if a.cmd == "hook":
        return hk.main(a.kind)
    if a.cmd == "version":
        print(VERSION)
        return 0
    root = find_root(a.root)
    if a.cmd == "survey":
        s = sv.survey(root)
        print(json.dumps({k: v for k, v in s.items() if k != "draft_canon"}, indent=1))
        if a.cards:
            p, n = sv.write_cards(root, s)
            print(f"{n} card(s) written to {p}")
    elif a.cmd == "adopt":
        print(
            "\n".join(sv.adopt(root, a.answers)) or "already adopted: nothing to write"
        )
    elif a.cmd == "capability":
        return cmd_capability(root, a)
    elif a.cmd == "move":
        try:
            message, written = mv.record_move(root, a.decision, a.base)
        except ValueError as error:
            print(f"refused: {error}")
            return 1
        print("\n".join([message, *written]))
    elif a.cmd == "gen":
        print("\n".join(arch_gen.gen(root)) or "generated files already current")
    elif a.cmd == "check":
        return cmd_check(root, a)
    elif a.cmd == "ratchet":
        print("removed (violations, legacy files):", ck.ratchet(root))
    elif a.cmd == "tighten":
        ck.tighten(root, a.rule, a.decision)
        print(
            f"now blocking: {', '.join(a.rule)} (decision {a.decision}); baseline updated"
        )
    elif a.cmd == "plan":
        return cmd_plan(root, a)
    elif a.cmd == "spec-block":
        print(
            "ARCH block added"
            if pl.spec_block(a.spec)
            else "ARCH block already present"
        )
    elif a.cmd == "exception":
        if a.action == "request":
            e = ax.request(root, a.rule, a.scope, a.reason)
            print(
                f"pending {e['id']}: card at {ac.decisions_dir() / e['file']}; answer it on the decisions page"
            )
        else:
            print("\n".join(ax.resolve(root)) or "nothing to resolve")
    elif a.cmd == "digest":
        cmd_digest(root, a)
    elif a.cmd == "lifecycle":
        return lc.main(
            [a.action, "--root", str(root)]
            + (["--base", a.base] if a.base else [])
            + (["--json"] if a.json else [])
        )
    elif a.cmd == "edit-check":
        lines, bad = hk.edit_check(root, a.files)
        print("\n".join(lines))
        return 1 if bad else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
