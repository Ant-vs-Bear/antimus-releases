#!/usr/bin/env python3
"""SPEC-ARCHITECT-ENFORCES-ONE-OWNER AC-03: one table of state transitions, checked for the three ways it can lie.

A transition TABLE is a list of rows: field, from, guard, to, owner, trigger ('timer' or 'event'), and optional exclusive_with
(guard ids that may not both fire). check() reports:
  conflict      two rows on the same field and from state, not mutually exclusive, that can both fire with different results
  cycle         a field whose from->to graph has a loop made only of timer edges (no outside event breaks it)
  second_writer a field whose rows name more than one owner
"""


def _exclusive(a, b):
    return b["guard"] in (a.get("exclusive_with") or []) or a["guard"] in (
        b.get("exclusive_with") or []
    )


def _conflicts(table):
    out = []
    for i, a in enumerate(table):
        for b in table[i + 1 :]:
            # same field and from state, not mutually exclusive, and not the same rule twice: two rules that can both fire
            if (
                a["field"] == b["field"]
                and a["from"] == b["from"]
                and (a["to"] != b["to"] or a["guard"] != b["guard"])
                and not _exclusive(a, b)
            ):
                out.append(
                    (
                        "conflict",
                        (
                            f"{a['field']}: {a['from']}->{a['to']} ({a['guard']}, {a['owner']}) and "
                            f"{b['from']}->{b['to']} ({b['guard']}, {b['owner']}) can both fire with different results"
                        ),
                    )
                )
    return out


def _has_cycle(edges):
    seen, stack = set(), set()

    def walk(node):
        if node in stack:
            return True
        if node in seen:
            return False
        seen.add(node)
        stack.add(node)
        found = any(walk(nxt) for nxt in edges.get(node, ()))
        stack.discard(node)
        return found

    return any(walk(n) for n in list(edges))


def _cycles(table):
    out = []
    for field in {r["field"] for r in table}:
        rows = [r for r in table if r["field"] == field]
        edges = {}
        for r in rows:
            if r["trigger"] == "timer":
                edges.setdefault(r["from"], set()).add(r["to"])
        if _has_cycle(edges):
            parts = ", ".join(
                f"{r['from']}->{r['to']} ({r['guard']}, {r['owner']})"
                for r in rows
                if r["trigger"] == "timer"
            )
            out.append(
                (
                    "cycle",
                    f"{field}: a loop of timer edges makes no progress without an outside event: {parts}",
                )
            )
    return out


def _second_writers(table):
    owners = {}
    for r in table:
        owners.setdefault(r["field"], set()).add(r["owner"])
    return [
        ("second_writer", f"{field}: more than one owner ({', '.join(sorted(names))})")
        for field, names in owners.items()
        if len(names) > 1
    ]


def check(table):
    """Every finding as (kind, message); empty when the table is consistent."""
    return _cycles(table) + _conflicts(table) + _second_writers(table)


# Today's real table for the admitted label. The three rows name three different owners, so check() reports
# second_writer as well as the conflict and cycle the admit/demote pair already has.
TRANSITIONS = [
    {
        "field": "admitted_label",
        "from": "idea",
        "guard": "admitter_sees_free_pane",
        "to": "admitted",
        "owner": "tools/spec-backlog/auto_admit.py",
        "trigger": "timer",
    },
    {
        "field": "admitted_label",
        "from": "admitted",
        "guard": "rebalancer_sees_no_pane",
        "to": "idea",
        "owner": "tools/steward/rebalance.py",
        "trigger": "timer",
    },
    {
        "field": "admitted_label",
        "from": "admitted",
        "guard": "ledger_does_not_back_label",
        "to": "idea",
        "owner": "tools/admission/admission_tick.py",
        "trigger": "timer",
    },
]


def main():
    findings = check(TRANSITIONS)
    for kind, message in findings:
        print(f"{kind}: {message}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
