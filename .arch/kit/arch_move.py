"""arch-kit move: record a pure path move in the architecture policy, citing a decision the founder already resolved.

When a folder or file is renamed, `.arch/canon.yaml`, `.arch/exceptions.yaml` and `.arch/baseline.json` change only by the
renamed paths. The policy check wants a resolved decision for any change to those files, and the architect hook stops agents
writing the log by hand, so a rename used to stop a window to ask the founder. This command proves the change is nothing but
renamed paths (git's own rename detection, similarity 90 percent or more), checks the cited decision is resolved, then logs it
through arch_config.log_decision and regenerates the docs. Anything else (a rule added, removed or loosened, a count raised,
an exception added) is refused: the founder must decide. It only reads decisions files and never edits policy content.
"""

import json
import re
from collections import Counter

import arch_config as ac
import arch_gen
import yaml

POLICY = ("canon.yaml", "exceptions.yaml", "baseline.json")
REF = re.compile(r"[\w.\-]+#\w+")
MAX_REPORT = 5


def rename_pairs(root, base):
    """(old, new) file renames between base and the working tree, by git rename detection at 90 percent similarity."""
    out = ac.git(root, "diff", "-M90%", "--name-status", "-z", base).split("\0")
    pairs, i = [], 0
    while i < len(out):
        status = out[i]
        if status.startswith("R") and i + 2 < len(out):
            pairs.append((out[i + 1], out[i + 2]))
            i += 3
        else:
            i += 2 if status else 1
    return pairs


def folder_gone(root, folder):
    return not ac.git(
        root, "ls-files", "-co", "--exclude-standard", "--", folder
    ).strip()


def path_map(root, base):
    """Path prefix -> new prefix, longest first: every renamed file, and every folder that moved as a whole."""
    pairs = rename_pairs(root, base)
    out = {old: new for old, new in pairs}
    for old, new in pairs:
        o, n = old.split("/"), new.split("/")
        while len(o) > 1 and len(n) > 1 and o[-1] == n[-1]:
            o, n = o[:-1], n[:-1]
            od, nd = "/".join(o), "/".join(n)
            if od != nd and folder_gone(root, od):
                out.setdefault(od, nd)
    return dict(sorted(out.items(), key=lambda kv: -len(kv[0])))


def substituter(mapping):
    if not mapping:
        return lambda s: s
    alt = "|".join(re.escape(k) for k in mapping)
    rx = re.compile(rf"(?<![\w.\-/])({alt})(?![\w.\-])")
    return lambda s: rx.sub(lambda m: mapping[m.group(1)], s)


def expected(obj, sub):
    """The old structure with every renamed path replaced, keys included. A key collision is not a rename."""
    if isinstance(obj, str):
        return sub(obj)
    if isinstance(obj, list):
        return [expected(x, sub) for x in obj]
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            nk = sub(k) if isinstance(k, str) else k
            if nk in out:
                raise ValueError(f"two entries collapse into {nk!r}")
            out[nk] = expected(v, sub)
        return out
    return obj


def canon_form(obj):
    """Order-free form: dicts sorted by key, lists sorted as multisets."""
    if isinstance(obj, dict):
        return {
            k: canon_form(v) for k, v in sorted(obj.items(), key=lambda kv: str(kv[0]))
        }
    if isinstance(obj, list):
        return sorted(
            (canon_form(x) for x in obj),
            key=lambda x: json.dumps(x, sort_keys=True, default=str),
        )
    return obj


def differences(want, got, where="", out=None):
    out = [] if out is None else out
    if len(out) >= MAX_REPORT:
        return out
    if isinstance(want, dict) and isinstance(got, dict):
        for k in sorted(set(want) | set(got), key=str):
            if k not in want:
                out.append(f"{where}/{k}: added (not a rename)")
            elif k not in got:
                out.append(f"{where}/{k}: removed (not a rename)")
            else:
                differences(want[k], got[k], f"{where}/{k}", out)
    elif isinstance(want, list) and isinstance(got, list):
        w, g = (
            Counter(json.dumps(x, sort_keys=True, default=str) for x in want),
            Counter(json.dumps(x, sort_keys=True, default=str) for x in got),
        )
        for item in w - g:
            out.append(f"{where}: expected {item} but it is not there")
        for item in g - w:
            out.append(f"{where}: {item} is new (not a rename)")
    elif want != got:
        out.append(f"{where}: {want!r} became {got!r} (not a rename)")
    return out[:MAX_REPORT]


def parse(name, text):
    if not text.strip():
        return {}
    return json.loads(text) if name.endswith(".json") else (yaml.safe_load(text) or {})


def changed_policy(root, base):
    """name -> (text at base, text now) for each policy file that differs."""
    out = {}
    for name in POLICY:
        p = ac.arch_path(root, name)
        now = p.read_text() if p.is_file() else ""
        was = ac.git(root, "show", f"{base}:{ac.ARCH_DIR}/{name}")
        if now != was:
            out[name] = (was, now)
    return out


def refusal(problems):
    return ValueError(
        "not a pure path move, so the founder must decide:\n  " + "\n  ".join(problems)
    )


def already_logged(root, base, ref):
    old = ac.git(root, "show", f"{base}:{ac.ARCH_DIR}/decisions.log").splitlines()
    return ref in ac.decision_refs_logged(root)[len([ln for ln in old if ln.strip()]) :]


def record_move(root, decision, base=None):
    """Returns (message, files written). Raises ValueError, writing nothing, when the change is not a pure move."""
    if not REF.fullmatch(decision or ""):
        raise ValueError(f"decision {decision!r} is not of the form <file>#<id>")
    if ac.resolve_decision_ref(decision) is None:
        raise ValueError(
            f"decision {decision!r} is not a resolved decision on the decisions page"
        )
    if ac.load_canon(root) is None:
        raise ValueError(
            "this repo has not adopted the architect (no .arch/canon.yaml)"
        )
    base = ac.base_ref(root, base)
    changed = changed_policy(root, base)
    if not changed:
        return "no policy file changed against the base: nothing to record", []
    sub = substituter(path_map(root, base))
    problems = []
    for name, (was, now) in changed.items():
        try:
            want, got = parse(name, was), parse(name, now)
            problems += [
                f".arch/{name}{d}"
                for d in differences(canon_form(expected(want, sub)), canon_form(got))
            ]
        except (ValueError, yaml.YAMLError) as error:
            problems.append(f".arch/{name}: {error}")
    if problems:
        raise refusal(problems[:MAX_REPORT])
    if already_logged(root, base, decision):
        return f"already recorded ({decision}): nothing to add", []
    ac.log_decision(root, decision)
    return (
        f"recorded a pure path move citing {decision}",
        [".arch/decisions.log", *arch_gen.gen(root)],
    )
