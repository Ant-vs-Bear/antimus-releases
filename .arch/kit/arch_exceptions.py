"""arch_exceptions: founder-approved exceptions, asked and answered asynchronously (SPEC-CHIEF-ARCHITECT section 5.10).

Hooks cannot wait for a human. An agent runs `request`; that writes .arch/pending.json and a card for the decisions page, and
`check` fails with "awaiting decision N" until the founder answers. The answer is turned into a scoped, expiring entry in
.arch/exceptions.yaml by `resolve`, which runs automatically at the start of every check, so the next session resumes with it.
Only the decisions page mints decision references; nothing else can add an exception.
"""

import datetime as dt
import subprocess
import sys
import time
from pathlib import Path

import arch_config as ac
import arch_scan as sc

DECIDE = Path(__file__).resolve().parents[1] / "spec-decide" / "spec_decide.py"
DAYS = {"a": 60, "b": 180}


def pending_path(root):
    return ac.arch_path(root, "pending.json")


def load_pending(root):
    return ac.load_json(pending_path(root), [])


def card(entry):
    return {
        "title": "Architecture exception request",
        "context": "An agent asked for permission to break an architecture rule. Nothing else is waiting on you.",
        "status": "pending",
        "budget": 5,
        "basis_unstated": True,
        "scope": {
            "will_build": "Allow the one exception below, for the time you choose.",
            "wont_build": "Any change to the rule itself.",
            "done_when": "You have chosen how long it is allowed, or said no.",
        },
        "decisions": [
            {
                "id": "d1",
                "kind": "question",
                "impact": "med",
                "title": f"Allow an exception to '{entry['rule']}'?",
                "plain_english": (
                    f"The code being written wants to break this architecture rule: {entry['rule']}, in {entry['scope']}. "
                    f"The agent's reason: {entry['reason']}. Approving lets this one case through for the time you pick, then it comes back for review."
                )[:880],
                "why_it_matters": "Exceptions that never expire become the new normal and bring the sprawl back.",
                "evidence": f"Raised {entry['created']}, request {entry['id']}.",
                "if_unsure": "Say no and ask for the existing module to be used or improved instead.",
                "reversible": "Yes. The exception expires on its own and can be removed at any time.",
                "options": [
                    {
                        "id": "a",
                        "label": "Approve for 60 days",
                        "consequence": "The case is allowed for 60 days, then it must be fixed or renewed.",
                        "recommended": False,
                    },
                    {
                        "id": "b",
                        "label": "Approve for 180 days",
                        "consequence": "Allowed for 180 days; fewer reminders, longer exposure.",
                    },
                    {
                        "id": "c",
                        "label": "No: use the existing module",
                        "consequence": "The agent must reuse or extend the canonical module.",
                        "recommended": True,
                    },
                    {"id": "other", "label": "Other"},
                ],
            }
        ],
    }


def request(root, rule, scope, reason, spec=None):
    """Create a pending exception and its decisions-page card. Returns the pending entry."""
    pid = f"p{int(time.time() * 1000)}"
    name = f"arch-exception-{pid}.decisions.json"
    entry = {
        "id": pid,
        "rule": rule,
        "scope": scope,
        "reason": reason,
        "spec": spec,
        "created": ac.today().isoformat(),
        "ref": f"{name}#d1",
        "file": name,
    }
    ac.decisions_dir().mkdir(parents=True, exist_ok=True)
    ac.save_json(ac.decisions_dir() / name, card(entry))
    r = subprocess.run(
        [sys.executable, str(DECIDE), "validate", str(ac.decisions_dir() / name)],
        capture_output=True,
        text=True,
        check=False,
    )
    if r.returncode != 0:
        raise RuntimeError(
            "generated exception card is invalid: " + (r.stdout + r.stderr)[:400]
        )
    ac.save_json(pending_path(root), load_pending(root) + [entry])
    return entry


def resolve(root, today=None):
    """Turn answered cards into exceptions (approve) or drop them (no). Returns a list of human-readable outcomes."""
    today = today or ac.today()
    pending, keep, outcomes = load_pending(root), [], []
    exceptions = ac.load_exceptions(root)
    for e in pending:
        d = ac.resolve_decision_ref(e["ref"])
        if d is None:
            keep.append(e)
            continue
        days = DAYS.get(d.get("answer"))
        if days:
            exceptions.append(
                {
                    "rule": e["rule"],
                    "scope": e["scope"],
                    "reason": e["reason"],
                    "decision_id": e["ref"],
                    "expires": (today + dt.timedelta(days=days)).isoformat(),
                }
            )
            ac.log_decision(root, e["ref"])
            outcomes.append(f"approved {e['rule']} for {days} days ({e['id']})")
        else:
            outcomes.append(
                f"declined {e['rule']} ({e['id']}): use the existing module"
            )
    if outcomes:
        ac.save_json(pending_path(root), keep)
        ac.save_yaml(ac.arch_path(root, "exceptions.yaml"), {"exceptions": exceptions})
    return outcomes


def pending_violations(root):
    """Violations for requests still waiting. Resolves answered ones first so the next session resumes with the decision."""
    if not pending_path(root).is_file():
        return []
    resolve(root)
    return [
        sc.violation(
            "pending.awaiting",
            e["scope"] if isinstance(e["scope"], str) else str(e["scope"]),
            e["id"],
            f"awaiting decision {e['id']}: exception for {e['rule']} ({e['reason']}); answer it on the decisions page",
        )
        for e in load_pending(root)
    ]
