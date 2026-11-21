"""Add one capability (a canonical module and bans on a second one) to the architecture policy.

The only sanctioned way to widen the rulebook after adoption: it needs a decision the founder has already resolved on the decisions page,
writes the capability, logs that decision in .arch/decisions.log (which is what the policy check looks for) and regenerates the docs.
"""

import re
from pathlib import Path

import arch_config as ac
import arch_gen

NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.]{1,60}")


def add_capability(root, name, canonical, bans, allow, note, decision):
    """Returns the files written. Raises ValueError, writing nothing, when any input is unusable."""
    canon = ac.load_canon(root)
    if canon is None:
        raise ValueError(
            "this repo has not adopted the architect (no .arch/canon.yaml)"
        )
    if not NAME.fullmatch(name or ""):
        raise ValueError("capability name must be letters, digits, '_' or '.'")
    if name in canon["capabilities"]:
        raise ValueError(f"capability {name!r} already exists")
    if not bans:
        raise ValueError("give at least one --ban pattern, or the rule bans nothing")
    if not canonical or not (Path(root) / canonical).is_file():
        raise ValueError(f"canonical file {canonical!r} does not exist in the repo")
    if ac.resolve_decision_ref(decision) is None:
        raise ValueError(
            f"decision {decision!r} is not a resolved decision on the decisions page"
        )
    canon["capabilities"][name] = {
        "canonical": canonical,
        "bans": list(bans),
        "allow": list(allow or []),
        "note": note or f"added with decision {decision}",
    }
    ac.save_yaml(ac.arch_path(root, "canon.yaml"), canon)
    ac.log_decision(root, decision)
    return [".arch/canon.yaml", ".arch/decisions.log", *arch_gen.gen(root)]
