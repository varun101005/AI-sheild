"""Stage 1: rule-based scan, the 'metal detector'. Fast and obvious cases only, no reasoning.
  Python               -> Bandit
  C and C++            -> flawfinder
  JavaScript, TypeScript, Java, HTML -> a small built-in table of line-by-line regex rules.
                          That table is NOT a real analyser: expect misses and false alarms, and let the LLM judge.

Fixes applied
-------------
FIX 6:  Deduplicate findings by (file, line, rule_id) so that one line matching
        multiple rules produces only the highest-severity entry, not duplicates.
FIX 6b: Tightened several regex patterns to reduce false positives:
        - eval rule now excludes 'eval_', 'evaluate', 'medieval', etc.
        - exec rule now requires it to be a standalone call, not a method suffix.
FIX 7:  flawfinder flag written as two tokens (--minlevel 3) for wider version
        compatibility (some older versions do not accept --minlevel=3).
"""
import csv
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ..schemas import Finding, Signals, Static

SEV = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
NAMES = {
    "CWE-89": "SQL injection", "CWE-78": "OS command injection", "CWE-798": "Hard-coded secret",
    "CWE-259": "Hard-coded password", "CWE-327": "Weak cryptography", "CWE-328": "Weak hash",
    "CWE-502": "Unsafe deserialization", "CWE-94": "Code injection", "CWE-22": "Path traversal",
    "CWE-295": "Certificate not verified", "CWE-377": "Insecure temp file", "CWE-120": "Buffer overflow",
}
C_EXT, WEB_EXT, JAVA_EXT = (".c", ".h", ".cpp", ".cc", ".hpp"), (".js", ".jsx", ".ts", ".tsx", ".html", ".htm"), (".java",)
SECRET = r"(?i)\b(api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*[\"'][^\"']{6,}[\"']"

# FIX 6b: tightened regex patterns to reduce false positives
WEB_RULES = [
    # 'eval(' but NOT 'eval_xxx(' / '.eval(' / 'evaluate(' etc.
    (r"(?<![.\w])eval\s*\(", "CWE-95", "Code injection (eval)", "high", "JS-EVAL"),
    (r"\bnew\s+Function\s*\(", "CWE-95", "Code injection (new Function)", "high", "JS-FUNC"),
    (r"\.(innerHTML|outerHTML)\s*=\s*[^\"'`\s]|document\.write(ln)?\s*\(|dangerouslySetInnerHTML", "CWE-79", "Cross-site scripting", "high", "JS-XSS"),
    # exec / execSync but NOT string.exec( or regex.exec( (must be a plain call)
    (r"(?<![.\w])(exec|execSync)\s*\(", "CWE-78", "OS command injection", "high", "JS-EXEC"),
    (r"createHash\(\s*[\"'](md5|sha1)[\"']", "CWE-327", "Weak hash", "medium", "JS-HASH"),
    (SECRET, "CWE-798", "Hard-coded secret", "medium", "JS-SECRET"),
]
JAVA_RULES = [
    (r"(?i)\"[^\"]*\b(select|insert|update|delete)\b[^\"]*\"\s*\+", "CWE-89", "SQL injection", "high", "JAVA-SQL"),
    (r"Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\(", "CWE-78", "OS command injection", "high", "JAVA-EXEC"),
    (r"MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"", "CWE-327", "Weak hash", "medium", "JAVA-HASH"),
    (r"new\s+ObjectInputStream\s*\(", "CWE-502", "Unsafe deserialization", "high", "JAVA-DESER"),
    (SECRET, "CWE-798", "Hard-coded secret", "medium", "JAVA-SECRET"),
]
RULES = {ext: [(re.compile(p), *r) for p, *r in rules] for exts, rules in ((WEB_EXT, WEB_RULES), (JAVA_EXT, JAVA_RULES)) for ext in exts}

# Severity order for deduplication (keep the highest)
_SEV_RANK = {"high": 0, "medium": 1, "low": 2}


def _tmp_copy(files, exts):
    tmp, kept = Path(tempfile.mkdtemp(prefix="csai_scan_")), 0
    for f in files:
        rel = Path(f.path)
        if rel.is_absolute() or ".." in rel.parts or rel.suffix.lower() not in exts:
            continue                                  # never write outside the temp folder
        (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp / rel).write_text(f.text, encoding="utf-8")
        kept += 1
    return tmp, kept


def _run_tool(module, args, tmp, missing):
    try:
        p = subprocess.run([sys.executable, "-m", module, *args, str(tmp)], capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{module} timed out.")
    if f"No module named {module}" in p.stderr:
        raise RuntimeError(missing)
    return p


def _bandit(files):
    tmp, kept = _tmp_copy(files, (".py",))
    try:
        if not kept:
            return []
        p = _run_tool("bandit", ["-r", "-f", "json", "-q"], tmp, "Bandit is not installed. Run: pip install bandit")
        try:
            report = json.loads(p.stdout)
        except json.JSONDecodeError:
            raise RuntimeError("Bandit gave unreadable output: " + p.stderr[:200])
        rows = []
        for r in report.get("results", []):
            cwe_id = (r.get("issue_cwe") or {}).get("id")
            cwe = f"CWE-{cwe_id}" if cwe_id else "CWE-unknown"
            rows.append((os.path.relpath(r["filename"], tmp).replace("\\", "/"), r["line_number"], cwe,
                         NAMES.get(cwe) or r.get("test_name", "issue").replace("_", " ").capitalize(),
                         SEV.get(r["issue_severity"], "low"), r["test_id"]))
        return rows
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _flawfinder(files):
    tmp, kept = _tmp_copy(files, C_EXT)
    try:
        if not kept:
            return []
        # FIX 7: use separate tokens for --minlevel to support older flawfinder versions
        p = _run_tool("flawfinder", ["--csv", "--minlevel", "3"], tmp,
                      "flawfinder is not installed. Run: pip install flawfinder")
        rows = []
        for r in csv.DictReader(io.StringIO(p.stdout)):
            lvl = int(r.get("Level") or 0)
            m = re.search(r"CWE-\d+", r.get("CWEs") or "")
            cwe = m.group(0) if m else "CWE-unknown"
            rows.append((os.path.relpath(r["File"], tmp).replace("\\", "/"), int(r["Line"]), cwe,
                         NAMES.get(cwe) or f"{r.get('Category', 'risk').capitalize()} risk ({r.get('Name')})",
                         "high" if lvl >= 4 else "medium" if lvl == 3 else "low", f"FF-{r.get('Name')}"))
        return rows
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _patterns(files):
    rows = []
    for f in files:
        rules = RULES.get(Path(f.path).suffix.lower())
        for no, line in enumerate(f.text.split("\n") if rules else [], 1):
            if len(line) > 2000:
                continue                              # minified code
            rows += [(f.path, no, cwe, name, sev, rid) for rx, cwe, name, sev, rid in rules if rx.search(line)]
    return rows


def _deduplicate(rows):
    """Keep only the highest-severity finding per (file, line, rule_id).
    FIX 6: prevents the same line matching multiple rules from flooding results.
    """
    best: dict = {}
    for row in rows:
        path, no, cwe, name, sev, rule = row
        key = (path, no, rule)
        existing = best.get(key)
        if existing is None or _SEV_RANK[sev] < _SEV_RANK[existing[4]]:
            best[key] = row
    return sorted(best.values(), key=lambda x: (x[0], x[1]))


def run(files, findings):
    rows = _deduplicate(_bandit(files) + _flawfinder(files) + _patterns(files))
    lines = {f.path: f.text.split("\n") for f in files}
    out = []
    for i, (path, no, cwe, name, sev, rule) in enumerate(rows, 1):
        src = lines.get(path, [])
        text = src[no - 1].strip() if 0 < no <= len(src) else ""
        out.append(Finding(id=f"F-{i:03d}", file=path, line=no, cwe=cwe, type=name, severity=sev,
                           signals=Signals(static=Static(hit=True, note=f"Rule {rule}")), code=[text]))
    return out
