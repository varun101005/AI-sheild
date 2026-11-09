"""Serving side of the ML classifier, in plain Python (no scikit-learn, no pickle files).
One model per language group, exported as JSON by ml/train_classifier.py:
  python (.py)   c_cpp (.c .h .cpp .cc .hpp)   java (.java)   js_ts (.js .jsx .ts .tsx and HTML, which shares the JS model)
Training and serving share features(), which keeps them identical."""
import ast
import json
import math
import os
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOKEN_RE = re.compile(r"[a-z_][a-z0-9_]*|\d+|[^\sa-z0-9_]")
MAX_CHARS = 8000
EXT_GROUP = {".py": "python", ".c": "c_cpp", ".h": "c_cpp", ".cpp": "c_cpp", ".cc": "c_cpp", ".hpp": "c_cpp", ".java": "java",
             ".js": "js_ts", ".jsx": "js_ts", ".ts": "js_ts", ".tsx": "js_ts", ".html": "js_ts", ".htm": "js_ts"}
_cache = {}


def lang_of(path):
    return EXT_GROUP.get(Path(path).suffix.lower())


def prep(code, lang="python"):
    if lang == "python":
        lines = [l.split("#", 1)[0].rstrip() for l in code.splitlines()]
    else:                                              # C-style comments; '#include' lines are kept
        lines = [l.split("//", 1)[0].rstrip() for l in re.sub(r"/\*.*?\*/", " ", code, flags=re.S).splitlines()]
    return "\n".join(l for l in lines if l.strip()).lower()


def features(code, lang="python"):
    t = TOKEN_RE.findall(prep(code, lang))
    return t + [a + " " + b for a, b in zip(t, t[1:])]


def _brace_unit(lines, line):
    """Smallest {...} block around the line whose header looks like a function (heuristic for C-style languages)."""
    stack, blocks = [], []
    for i, l in enumerate(lines):
        s = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '""', l).split("//")[0]
        for ch in s:
            if ch == "{":
                stack.append(i)
            elif ch == "}" and stack:
                blocks.append((stack.pop(), i))
    best = None
    for o, c in blocks:
        if not o <= line - 1 <= c:
            continue
        head = o if "(" in lines[o] else o - 1
        if head < 0 or "(" not in lines[head] or re.match(r"\s*(if|for|while|switch|else|catch|try|do|synchronized)\b", lines[head]):
            continue
        if best is None or c - head < best[1] - best[0]:
            best = (head, c)
    return "\n".join(lines[best[0]:best[1] + 1])[:MAX_CHARS] if best else None


def unit_for(text, line, window=8, lang="python"):
    """The code unit the model scores: the function around the flagged line (as in training), else a small window."""
    lines = text.split("\n")
    if lang != "python":
        unit = _brace_unit(lines, line)
        return unit if unit else "\n".join(lines[max(0, line - 1 - window):line + window])[:MAX_CHARS]
    best = None
    try:
        for n in ast.walk(ast.parse(text)):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.lineno <= line <= n.end_lineno:
                if best is None or n.end_lineno - n.lineno < best.end_lineno - best.lineno:
                    best = n
    except (SyntaxError, ValueError):
        pass
    if best:
        return "\n".join(lines[best.lineno - 1:best.end_lineno])[:MAX_CHARS]
    return "\n".join(lines[max(0, line - 1 - window):line + window])[:MAX_CHARS]


def _model_path(lang):
    if lang == "python" and os.getenv("ML_MODEL"):
        return Path(os.environ["ML_MODEL"])
    base = Path(os.getenv("ML_MODEL_DIR", ROOT / "ml" / "model"))
    p = base / f"classifier_{lang}.json"
    return base / "classifier.json" if lang == "python" and not p.exists() else p      # older Python-only file name


def load_model(lang="python"):
    path = _model_path(lang)
    try:
        stamp = (str(path), path.stat().st_mtime)
    except OSError:
        return None
    if _cache.get(str(path), (None,))[0] != stamp:
        try:
            _cache[str(path)] = (stamp, json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            return None
    return _cache[str(path)][1]


def score(model, code):
    """Probability-like score between 0 and 1 that the code unit is vulnerable (not calibrated)."""
    feats = model["features"]
    counts = Counter(f for f in features(code, model.get("lang", "python")) if f in feats)
    vec = {f: (1 + math.log(c)) * feats[f][0] for f, c in counts.items()}
    norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
    z = model["intercept"] + sum(v / norm * feats[f][1] for f, v in vec.items())
    return 1 / (1 + math.exp(-max(-60.0, min(60.0, z))))
