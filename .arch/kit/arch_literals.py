"""arch_literals: finds a number, limit, duration or key defined in more than one place in Python, TypeScript and Rust,
without being told what to look for (SPEC-ARCH-CHECK-FINDS-DUPLICATES-ON-ITS-OWN).

One generic extractor per language reads shared-looking constants (UPPER_CASE names, and lower-case names that read as a
limit), normalises units and numbers written in words, and clusters by concept. A cluster with more than one distinct
value is a divergence. Standard library only: Python is read with `ast`; TypeScript and Rust with line patterns."""

import ast
import hashlib
import re
from collections import defaultdict
from pathlib import Path

LANGS = {
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "typescript",
    ".jsx": "typescript",
    ".mjs": "typescript",
    ".cjs": "typescript",
    ".rs": "rust",
}
SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "target",
    "vendor",
    ".next",
    ".venv",
    "venv",
    "__pycache__",
    ".worktrees",
    "coverage",
    "generated",
    "migrations",
}
GENERATED_RE = re.compile(r"\.(d\.ts|min\.js|generated\.\w+|pb\.\w+)$|(^|/)gen/")
TEST_RE = re.compile(
    r"(^|/)(tests?|__tests__|fixtures?)/|(^|/)test_[^/]*$|_test\.\w+$|\.(test|spec)\.\w+$|(^|/)conftest\.py$"
)
MAX_BYTES = 1_000_000

# Idiom literals that carry no ownership: tiny numbers, round percentages, HTTP statuses.
IDIOMS = {
    0,
    1,
    2,
    3,
    10,
    100,
    1000,
    200,
    201,
    204,
    301,
    302,
    304,
    400,
    401,
    403,
    404,
    409,
    422,
    429,
    500,
    502,
    503,
}

WORDS = {
    w: n
    for n, w in enumerate(
        [
            "zero",
            "one",
            "two",
            "three",
            "four",
            "five",
            "six",
            "seven",
            "eight",
            "nine",
            "ten",
            "eleven",
            "twelve",
            "thirteen",
            "fourteen",
            "fifteen",
            "sixteen",
            "seventeen",
            "eighteen",
            "nineteen",
            "twenty",
        ]
    )
}
WORDS.update(
    {"thirty": 30, "forty": 40, "fifty": 50, "sixty": 60, "hundred": 100, "dozen": 12}
)
UNIT_SECONDS = {
    "ms": 0.001,
    "millis": 0.001,
    "milliseconds": 0.001,
    "s": 1,
    "sec": 1,
    "secs": 1,
    "seconds": 1,
    "min": 60,
    "mins": 60,
    "minutes": 60,
    "h": 3600,
    "hr": 3600,
    "hours": 3600,
}
ALIASES = {
    "dev": "developer",
    "devs": "developer",
    "num": "",
    "n": "",
    "count": "",
    "default": "",
    "const": "",
}
LIMIT_WORDS = {
    "max",
    "limit",
    "timeout",
    "per",
    "interval",
    "delay",
    "wait",
    "retries",
    "ttl",
    "size",
    "cap",
    "after",
    "gap",
}

GENERIC = {
    "limit",
    "max",
    "min",
    "size",
    "mark",
    "marker",
    "value",
    "name",
    "key",
    "model",
    "branch",
    "guard",
    "live",
    "matcher",
    "file",
    "path",
    "id",
    "type",
    "text",
    "url",
    "age",
    "day",
    "after",
    "stale",
    "cap",
}
PY_NAME_OK = re.compile(r"^[A-Za-z_]\w*$")
TS_RE = re.compile(
    r"""^\s*(?:export\s+)?(?:declare\s+)?(?:(?:const|let|var|readonly|static|public|private)\s+)*
        ([A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]|. ]+?)?\s*[=:]\s*
        (-?\d[\d_]*(?:\.\d+)?(?:\s*\*\s*\d[\d_]*(?:\.\d+)?)*|"[^"\n]{1,64}"|'[^'\n]{1,64}')\s*[;,]?\s*(?://.*)?$""",
    re.VERBOSE,
)
RS_RE = re.compile(
    r"""^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const|static)\s+([A-Z_][A-Z0-9_]*)\s*:\s*[^=]+?=\s*
        (.+?)\s*;""",
    re.VERBOSE,
)
RS_DURATION = re.compile(r"from_(secs|millis|mins|minutes)\(\s*([\d_]+)\s*\)")
NUM_EXPR = re.compile(
    r"^-?\d[\d_]*(?:\.\d+)?(?:[iu](?:8|16|32|64|128|size)|f32|f64)?(?:\s*\*\s*\d[\d_]*(?:\.\d+)?(?:[iu](?:8|16|32|64|128|size))?)*$"
)


# bracket/string/comment balance scan for TypeScript and Rust; arch_blind re-exports it
OPEN, CLOSE = "([{", ")]}"
REGEX_PREV = set("(,=:[!&|?{;") | {
    ""
}  # no "}": in JSX `{a}/{b}` the slash is text, not a regex


def _skip_string(text, i, quote):
    """Index just past a quoted string that starts at `i` (text[i] == quote), or None when it does not close on the
    same line. Backslash escapes are honoured."""
    n = len(text)
    j = i + 1
    while j < n and text[j] != quote:
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == "\n":
            return None
        j += 1
    if j >= n or text[j] != quote:
        return None
    return j + 1


def _skip_regex(text, i):
    """Index just past a regex literal that starts at `i` (text[i] == '/'), or None when it does not close on the
    same line."""
    n = len(text)
    j, cls = i + 1, False
    while j < n and text[j] != "\n" and (cls or text[j] != "/"):
        if text[j] == "\\":
            j += 1
        elif text[j] == "[":
            cls = True
        elif text[j] == "]":
            cls = False
        j += 1
    if j < n and text[j] == "/":
        return j + 1
    return None


def check_balanced(text, lang):
    """Raise SyntaxError when strings, comments or brackets do not close: the file cannot be read as that language.
    Template literals are tracked with a stack so ${...} expressions are scanned as code; a single quote that does
    not close on its line is JSX text, not a string; '/' is a regex only after REGEX_PREV and never after '<' or
    before '>'."""
    stack, i, n, prev = [], 0, len(text), ""
    while i < n:
        c = text[i]
        two = text[i : i + 2]
        if stack and stack[-1] == "template":
            # inside a template literal: only ` closes it, ${ opens an expression
            if c == "\\" and i + 1 < n:
                # skip the escaped character; a dangling backslash falls through and the
                # unterminated template is reported as an unclosed bracket
                i += 2
                continue
            if c == "`":
                stack.pop()
                i, prev = i + 1, "`"
                continue
            if two == "${":
                stack.append("expr")
                i, prev = i + 2, "{"
                continue
            i += 1
            continue
        if two == "//":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if two == "/*":
            j = text.find("*/", i + 2)
            if j < 0:
                raise SyntaxError("unterminated block comment")
            i = j + 2
            continue
        if c == "`":
            stack.append("template")
            i, prev = i + 1, "`"
            continue
        if c == '"':
            end = _skip_string(text, i, c)
            if end is None:
                raise SyntaxError("unterminated string")
            i, prev = end, c
            continue
        if c == "'" and lang == "typescript":
            # JSX text: an apostrophe inside a word (don't) is text, not a string. Only the
            # character immediately before it decides, so a string after a keyword or a space
            # (return 'a(b') is still read as a string and its brackets are not scanned.
            if i and (text[i - 1].isalnum() or text[i - 1] == "_"):
                i, prev = i + 1, c
                continue
            end = _skip_string(text, i, c)
            if end is not None:
                i, prev = end, c
            else:
                i, prev = i + 1, c
            continue
        if (
            c == "/"
            and lang == "typescript"
            and prev in REGEX_PREV
            and prev != "<"
            and not (i + 1 < n and text[i + 1] == ">")
        ):
            end = _skip_regex(text, i)
            if end is not None:
                i, prev = end, "x"
                continue
        if c in OPEN:
            stack.append(c)
        elif c in CLOSE:
            if not stack:
                raise SyntaxError(f"unmatched {c!r}")
            top = stack.pop()
            if top == "expr":
                if c != "}":
                    raise SyntaxError(f"unmatched {c!r}")
            elif top in OPEN and OPEN.index(top) != CLOSE.index(c):
                raise SyntaxError(f"unmatched {c!r}")
        if not c.isspace():
            prev = c
        i += 1
    if stack:
        raise SyntaxError("unclosed bracket")


def tokens(name):
    """Name -> list of lower-case words (snake and camel case)."""
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name.replace("$", "_"))
    return [t for t in name.lower().split("_") if t]


def concept(name):
    """The words that say what the value is: units and filler removed, plurals and abbreviations folded."""
    out = []
    for t in tokens(name):
        if t in UNIT_SECONDS:
            continue
        t = ALIASES.get(t, t)
        if len(t) > 4 and t.endswith("ies"):
            t = t[:-3] + "y"
        elif len(t) > 3 and t.endswith("s") and not t.endswith("ss"):
            t = t[:-1]
        if t:
            out.append(t)
    return tuple(sorted(set(out)))


def unit_factor(name):
    last = tokens(name)[-1:] or [""]
    return UNIT_SECONDS.get(last[0], 1), last[0] in UNIT_SECONDS


def number(raw):
    """A number, or a number written in words, or None."""
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        return raw
    s = str(raw).strip().strip("'\"").lower().replace("_", "")
    s = re.sub(r"(?<=\d)[iu](?:8|16|32|64|128|size)$|(?<=\d)f(?:32|64)$", "", s)
    if s in WORDS:
        return WORDS[s]
    m = re.fullmatch(r"-?\d+(?:\.\d+)?(?:\s*\*\s*\d+(?:\.\d+)?)*", s)
    if m:
        v = 1.0
        for p in s.split("*"):
            v *= float(p)
        return int(v) if v == int(v) else v
    return None


def _interesting(name, value):
    if not isinstance(value, (int, float)):
        return name.isupper() and len(name) > 3
    if value in IDIOMS:
        return False
    if name.isupper() or "_" in name and name.upper() == name:
        return True
    return bool(set(tokens(name)) & LIMIT_WORDS)


def _item(lang, rel, line, name, value, raw):
    factor, has_unit = unit_factor(name)
    v = value
    if isinstance(v, (int, float)) and has_unit:
        v = v * factor
        v = int(v) if v == int(v) else v
    return {
        "lang": lang,
        "file": rel,
        "line": line,
        "name": name,
        "raw": raw,
        "value": v,
        "concept": concept(name),
    }


def _py_value(node):
    if isinstance(node, ast.Constant) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mult, ast.Add)):
        a, b = _py_value(node.left), _py_value(node.right)
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            return a * b if isinstance(node.op, ast.Mult) else a + b
    return None


def extract_python(text, rel):
    tree = ast.parse(text)
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, val = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            target, val = node.target, node.value
        else:
            continue
        if not isinstance(target, ast.Name) or not PY_NAME_OK.match(target.id):
            continue
        v = _py_value(val)
        if v is None:
            continue
        w = number(v) if isinstance(v, str) else v
        if isinstance(v, str) and w is None and not target.id.isupper():
            continue
        v = w if w is not None else v
        if _interesting(target.id, v):
            out.append(
                _item(
                    "python",
                    rel,
                    node.lineno,
                    target.id,
                    v,
                    ast.get_source_segment(text, val) or "",
                )
            )
    return out


def extract_typescript(text, rel):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = TS_RE.match(line)
        if not m:
            continue
        name, raw = m.group(1), m.group(2)
        v = number(raw)
        if v is None:
            v = raw.strip("'\"")
        if _interesting(name, v):
            out.append(_item("typescript", rel, i, name, v, raw))
    return out


def extract_rust(text, rel):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = RS_RE.match(line)
        if not m:
            continue
        name, expr = m.group(1), m.group(2).strip()
        d = RS_DURATION.search(expr)
        if d:
            f = {"secs": 1, "millis": 0.001, "mins": 60, "minutes": 60}[d.group(1)]
            v = number(d.group(2)) * f
            v = int(v) if v == int(v) else v
            item = _item("rust", rel, i, name, v, expr)
            item["value"] = v
            if _interesting(name, v):
                out.append(item)
            continue
        if NUM_EXPR.match(expr):
            v = number(expr)
        elif expr.startswith('"') and expr.endswith('"') and len(expr) <= 66:
            v = expr.strip('"')
        else:
            continue
        if v is not None and _interesting(name, v):
            out.append(_item("rust", rel, i, name, v, expr))
    return out


EXTRACTORS = {
    "python": extract_python,
    "typescript": extract_typescript,
    "rust": extract_rust,
}


def source_files(root):
    """Source files in the three languages, test files and generated folders left out. Returns (rel path, lang)."""
    root = Path(root)
    out = []
    for p in sorted(root.rglob("*")):
        if p.suffix not in LANGS or not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if any(part in SKIP_DIRS for part in rel.split("/")[:-1]):
            continue
        out.append((rel, LANGS[p.suffix]))
    return out


def extract_file(root, rel, lang):
    """Items from one file; raises SyntaxError or ValueError when the file cannot be read as that language."""
    p = Path(root) / rel
    if p.stat().st_size > MAX_BYTES:
        raise ValueError("larger than 1 MB")
    text = p.read_text(encoding="utf-8")
    if "\0" in text:
        raise ValueError("binary content")
    if lang != "python":
        # lazy import: arch_blind imports arch_literals at module level, so importing it here
        # (inside the function) avoids a circular import at load time
        import arch_blind

        arch_blind.parse_check(text, lang, rel)
    return EXTRACTORS[lang](text, rel)


def extract(root):
    """All items across the repository, skipping files that cannot be read (arch_blind reports those)."""
    items = []
    for rel, lang in source_files(root):
        if TEST_RE.search(rel) or GENERATED_RE.search(rel):
            continue
        try:
            items += extract_file(root, rel, lang)
        except (SyntaxError, ValueError, UnicodeDecodeError, OSError):
            continue
    return items


def _jaccard(a, b):
    return len(set(a) & set(b)) / len(set(a) | set(b)) if a and b else 0.0


def cluster(items):
    """Group items that name the same concept in 2+ files. Returns clusters with a stable id, sites and divergence flag."""
    parent = list(range(len(items)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    by_concept = defaultdict(list)
    for i, it in enumerate(items):
        c = it["concept"]
        if c and (
            len(c) > 1
            or (isinstance(it["value"], (int, float)) and not set(c) <= GENERIC)
        ):
            by_concept[c].append(i)
    for idx in by_concept.values():
        for j in idx[1:]:
            parent[find(j)] = find(idx[0])
    keys = list(by_concept)
    for a in range(len(keys)):
        for b in range(a + 1, len(keys)):
            ka, kb = keys[a], keys[b]
            if len(set(ka) & set(kb)) >= 2 and _jaccard(ka, kb) >= 0.67:
                parent[find(by_concept[kb][0])] = find(by_concept[ka][0])
    groups = defaultdict(list)
    for idx in by_concept.values():
        for i in idx:
            groups[find(i)].append(items[i])
    out = []
    for g in groups.values():
        files = {(it["file"]) for it in g}
        if len(files) < 2:
            continue
        words = sorted({w for it in g for w in it["concept"]})
        cid = "-".join(words)
        values = sorted({str(it["value"]) for it in g})
        out.append(
            {
                "id": cid,
                "fingerprint": "cl-" + hashlib.sha1(cid.encode()).hexdigest()[:10],
                "sites": len(g),
                "files": sorted(files),
                "values": values,
                "divergence": len(values) > 1,
                "items": g,
            }
        )
    return sorted(out, key=lambda c: (not c["divergence"], c["id"]))


def report_line(c):
    tag = "DIVERGENCE" if c["divergence"] else "duplicate"
    return f"{tag} {c['id']}: {c['sites']} sites in {len(c['files'])} files, values {', '.join(c['values'])}"
