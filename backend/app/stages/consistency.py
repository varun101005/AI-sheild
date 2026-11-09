"""Our new idea 1 (Day 7): the rename test.
Ask the same question again with the variable names changed. A real finding should keep its
verdict; if the verdict flips, the LLM was reacting to names like 'password' instead of to logic.
runs  = 1 original + the renamed variants that answered
same  = how many of those runs gave the original verdict (the original itself counts)"""
import ast
import builtins
import re
from pathlib import Path

from . import llm_reasoning as L
from ..classifier_model import lang_of
from ..llm_client import LLMError, complete, config
from ..schemas import Consistency

STATUS = "not run"
MAX_TESTED = 10                                   # cost guard: each finding costs 2 extra LLM calls
SCHEMES = [lambda i: f"v{i}", lambda i: f"item_{chr(97 + i % 26)}{i}"]
ORDER = ("high", "medium", "low")


def _plan(tree):
    """Which names are safe to rename everywhere in the file."""
    bound, skip = set(), set(dir(builtins)) | {"self", "cls", "_"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            bound.add(n.id)
        elif isinstance(n, ast.arg):
            bound.add(n.arg)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            skip.update((a.asname or a.name).split(".")[0] for a in n.names)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.ExceptHandler)) and n.name:
            skip.add(n.name)
        elif isinstance(n, ast.JoinedStr):         # names inside f-strings: leave alone (positions are unreliable)
            skip.update(m.id for m in ast.walk(n) if isinstance(m, ast.Name))
        elif isinstance(n, ast.keyword) and n.arg:
            skip.add(n.arg)
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            skip.update(n.names)
        elif type(n).__name__.startswith("Match"):
            skip.update(x for x in (getattr(n, "name", None), getattr(n, "rest", None)) if isinstance(x, str))
    taken = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.arg for n in ast.walk(tree) if isinstance(n, ast.arg)} \
        | {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | skip
    return sorted(x for x in bound - skip if not (x.startswith("__") and x.endswith("__"))), taken


def _rename(text, tree, names, taken, scheme):
    new, used = {}, set(taken)
    for i, old in enumerate(names, 1):
        cand = scheme(i)
        while cand in used:
            cand += "_"
        used.add(cand)
        new[old] = cand
    edits = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and n.id in new:
            edits.add((n.lineno, n.col_offset, n.id))
        elif isinstance(n, ast.arg) and n.arg in new:
            edits.add((n.lineno, n.col_offset, n.arg))
    lines = text.split("\n")
    for ln, col, old in sorted(edits, reverse=True):
        line = lines[ln - 1]
        c = len(line.encode()[:col].decode(errors="ignore"))   # AST offsets are UTF-8 bytes
        if line[c:c + len(old)] != old:
            return None                                          # position did not line up: unsafe, drop variant
        lines[ln - 1] = line[:c] + new[old] + line[c + len(old):]
    return lines


TOK = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|`(?:\\.|[^`\\])*`|//[^\n]*|/\*.*?\*/|[A-Za-z_$][\w$]*|\s+|.', re.S)
ID = re.compile(r"[A-Za-z_$][\w$]*")
CTRL = {"if", "for", "while", "switch", "catch", "with", "synchronized", "return", "sizeof", "typeof"}
NOT_TYPE = {"return", "else", "new", "throw", "case", "goto", "delete", "typeof", "in", "of", "instanceof", "extends", "implements",
            "import", "package", "include", "define", "do", "yield", "await", "throws"}
RESERVED = set(NOT_TYPE | CTRL | set("""auto break char const continue default double enum extern float inline int long register short signed
    static struct union unsigned void volatile class public private protected this namespace template typename using virtual override final
    abstract interface boolean byte transient native let var function async export from as null true false undefined NULL nullptr EOF String
    Object Array Math console window document super self cls int8_t uint8_t size_t main""".split()))


def _variants_other(text, lang):
    """Same idea for C, C++, Java, JavaScript, TypeScript and HTML: rename declared variables and parameters with a token
    scan (strings, comments, member names and object keys are left alone). A heuristic, not a parser."""
    toks = [m.group() for m in TOK.finditer(text)]
    inert = lambda t: t.isspace() or t.startswith(("//", "/*")) or t[0] in "\"'`"
    ct = [t for t in toks if not inert(t)]
    isid = lambda t: bool(ID.fullmatch(t))
    skip, tpl, declared, params, pair, stack = set(), set(), set(), set(), {}, []
    for t in toks:
        if t.startswith("`"):                                   # names used inside template literals stay as they are
            for m in re.finditer(r"\$\{([^}]*)\}", t):
                tpl.update(ID.findall(m.group(1)))
    for k, t in enumerate(ct):
        if t == "(":
            stack.append(k)
        elif t == ")" and stack:
            pair[stack.pop()] = k
    for k, t in enumerate(ct):
        prev, nxt = (ct[k - 1] if k else ""), (ct[k + 1] if k + 1 < len(ct) else "")
        if isid(t) and nxt == ":" and prev in ("{", ","):
            skip.add(t)                                          # object key
        if t in ("let", "const", "var") and isid(nxt):
            declared.add(nxt)
        if lang == "js_ts" and isid(t) and nxt == "=>":
            declared.add(t)
        if lang != "js_ts" and isid(t) and nxt in ("=", ";", ",", "[", ")") and prev not in NOT_TYPE \
                and ((isid(prev) and prev not in CTRL) or (prev in (">", "*", "&", "]") and k > 1 and (isid(ct[k - 2]) or ct[k - 2] in (">", "*", "&", "]")))):
            declared.add(t)
        if t == "(" and k in pair and ct[k - 1:k] and ct[k - 1] not in CTRL and pair[k] + 1 < len(ct) \
                and (ct[pair[k] + 1] in ("{", "=>", "throws", "const", "noexcept", "override") or (lang == "js_ts" and ct[pair[k] + 1] == ":")):   # TS return type
            seg, depth = [], 0
            for x in ct[k + 1:pair[k]] + [","]:
                depth += x in "([{<" and 1 or -(x in ")]}>")
                if x == "," and depth <= 0:
                    head = seg[:seg.index("=")] if "=" in seg else seg
                    ids = [y for y in head if isid(y) and y not in RESERVED]
                    if ids:
                        params.add(ids[0] if ":" in head else ids[-1])    # TS "name: type" looks like an object key, so params win
                    seg, depth = [], 0
                else:
                    seg.append(x)
    names = sorted(n for n in ((declared - skip) | params) - tpl - RESERVED if not n.startswith("__"))
    if not names:
        return []
    taken = {t for t in ct if isid(t)} | RESERVED
    out = []
    for scheme in SCHEMES:
        new, used = {}, set(taken)
        for i, old in enumerate(names, 1):
            cand = scheme(i)
            while cand in used:
                cand += "_"
            used.add(cand)
            new[old] = cand
        res, p1, p2 = [], "", ""
        for t in toks:
            if inert(t):
                res.append(t)
                continue
            member = p1 in (".",) or (p1 == ">" and p2 == "-") or (p1 == ":" and p2 == ":")
            res.append(new[t] if t in new and not member else t)
            p1, p2 = t, p1
        out.append("".join(res).split("\n"))
    return out


def _variants(text, lang="python"):
    """Renamed copies of the file with identical line numbers. Empty if the file cannot be renamed."""
    if lang is None:
        return []
    if lang != "python":
        return _variants_other(text, lang)
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    names, taken = _plan(tree)
    if not names:
        return []
    out = [_rename(text, tree, names, taken, s) for s in SCHEMES]
    return [v for v in out if v]


def run(files, findings):
    global STATUS
    if not config():
        STATUS = "skipped (LLM not configured)"
        return findings
    cfg = config()
    texts = {f.path: f.text for f in files}
    cache = {}
    todo = sorted((f for f in findings if f.llm_checked), key=lambda f: ORDER.index(f.severity))[:MAX_TESTED]
    tested = stable = 0
    for f in todo:
        variants = cache.setdefault(f.file, _variants(texts.get(f.file, ""), lang_of(f.file)))
        runs = same = 1                                           # the original answer counts as run 1
        for lines in variants:
            try:
                verdict = L._parse(complete(cfg, L.SYSTEM, L._prompt(f, lines)))[0]
            except (LLMError, ValueError, TypeError):
                continue
            runs += 1
            same += verdict == f.signals.llm.verdict
        if runs > 1:
            f.consistency = Consistency(runs=runs, same=same)
            tested += 1
            stable += same == runs
    STATUS = (f"{stable} of {tested} tested findings kept the same verdict across renamed variants"
              if tested else "no findings could be tested")
    return findings
