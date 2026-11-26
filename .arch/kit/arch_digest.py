"""arch_digest: counts and changes, no prose (SPEC-CHIEF-ARCHITECT section 4 journey J6, decision d8).

Records the architecture health numbers each week in .arch/digest.json and renders a short table with a sparkline per metric.
`digest_card` turns the table into a decisions-page file so the founder sees it with the other pending items.
"""

import datetime as dt
from collections import defaultdict
from pathlib import Path

import arch_check as ck
import arch_config as ac

BARS = "▁▂▃▄▅▆▇█"


def metrics(root, canon, today=None):
    today = today or ac.today()
    viols, files, _ = ck.current_violations(root, canon)
    by = defaultdict(int)
    for v in viols:
        by[
            v["rule"].split(".")[0] if not v["rule"].startswith("canon.") else v["rule"]
        ] += 1
    legacy = (canon.get("layers") or {}).get("legacy", [])
    soon = 0
    for e in ac.load_exceptions(root):
        try:
            soon += (dt.date.fromisoformat(str(e.get("expires"))) - today).days <= 14
        except ValueError:
            pass
    m = {
        "legacy_to_new_edges": by.get("layer", 0),
        "duplicate_blocks": by.get("dup", 0),
        "loose_files": by.get("loose", 0),
        "legacy_lines": sum(
            ck.line_count(root, f)
            for f in files
            if legacy and ac.matches(f, legacy) and f.endswith(ac.SOURCE_EXTS)
        ),
        "exceptions_expiring_14d": soon,
        "pending_requests": len(ac.load_json(ac.arch_path(root, "pending.json"), [])),
    }
    for k, n in by.items():
        if k.startswith("canon."):
            m["banned_use:" + k[6:]] = n
    return m


def spark(values):
    if not values:
        return ""
    lo, hi = min(values), max(values)
    return "".join(
        BARS[0 if hi == lo else int((v - lo) / (hi - lo) * (len(BARS) - 1))]
        for v in values
    )


def record(root, today=None):
    """Append this week's numbers (one entry per date) and return the history."""
    root = Path(root)
    canon = ac.load_canon(root)
    today = today or ac.today()
    p = ac.arch_path(root, "digest.json")
    hist = ac.load_json(p, [])
    entry = {"date": today.isoformat(), **metrics(root, canon, today)}
    hist = [h for h in hist if h["date"] != entry["date"]] + [entry]
    ac.save_json(p, hist[-52:])
    return hist[-52:]


def table(hist):
    cur = hist[-1]
    prev = hist[-2] if len(hist) > 1 else None
    rows = ["| Measure | Now | Change | Last 8 |", "|---|---|---|---|"]
    for k, v in cur.items():
        if k == "date":
            continue
        d = "" if prev is None or k not in prev else f"{v - prev[k]:+d}"
        rows.append(
            f"| {k} | {v} | {d or '-'} | {spark([h.get(k, 0) for h in hist[-8:]])} |"
        )
    return f"Architecture digest {cur['date']}\n\n" + "\n".join(rows)


def digest_card(root, hist):
    name = f"arch-digest-{Path(root).name}-{hist[-1]['date']}.decisions.json"
    card = {
        "title": f"Weekly architecture digest: {Path(root).name}",
        "status": "pending",
        "budget": 5,
        "context": table(hist),
        "basis_unstated": True,
        "scope": {
            "will_build": "Nothing: this is a weekly summary.",
            "wont_build": "Any change.",
            "done_when": "You have glanced at the numbers.",
        },
        "decisions": [
            {
                "id": "d1",
                "kind": "assumption",
                "impact": "low",
                "title": "Seen this week's numbers",
                "why_it_matters": "A rising number means sprawl is coming back.",
                "evidence": "arch-kit digest",
                "if_unsure": "Acknowledge.",
                "reversible": "Yes.",
                "options": [
                    {
                        "id": "a",
                        "label": "Seen",
                        "consequence": "Nothing changes.",
                        "recommended": True,
                    },
                    {
                        "id": "b",
                        "label": "Something looks wrong: investigate",
                        "consequence": "The next session investigates the rising number.",
                    },
                    {"id": "other", "label": "Other"},
                ],
            }
        ],
    }
    ac.decisions_dir().mkdir(parents=True, exist_ok=True)
    p = ac.decisions_dir() / name
    ac.save_json(p, card)
    return p
