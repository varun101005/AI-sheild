"""Rule scanners for JavaScript, Java, C and HTML, plus the LLM path, against a fake LLM server."""
import json, os, sys, tempfile, threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.inputs import SourceFile, collect
from app.pipeline import run_pipeline
from app.schemas import ScanRequest
from app.stages import static_analysis

try:
    import flawfinder  # noqa: F401
    HAVE_FF = True
except ImportError:
    HAVE_FF = False

JS = "const el = document.getElementById('out');\nfunction show(name) {\n  el.innerHTML = name;\n}\n"
JAVA = 'class A {\n  void f(Statement s, String x) throws Exception {\n    s.executeQuery("SELECT * FROM t WHERE a=\'" + x + "\'");\n    Runtime.getRuntime().exec(x);\n  }\n}\n'
C = "#include <string.h>\nvoid f(char *s) {\n  char buf[8];\n  strcpy(buf, s);\n}\n"
HTML = "<button onclick=\"go()\">x</button>\n<script>\n  document.write(location.hash);\n</script>\n"
LEAD = '[{"line":1,"cwe":"CWE-1","type":"Odd lead","severity":"low","confidence":0.4,"explanation":"x"},{"line":3,"cwe":"CWE-79","type":"dup","severity":"high","confidence":0.9},{"line":99,"cwe":"CWE-1","type":"Invented","severity":"low"}]'
VERDICT = '{"verdict":"exploitable","score":0.9,"explanation":"User input reaches innerHTML."}'
PATCH = '{"start_line":3,"end_line":3,"replacement":"  el.textContent = name;","imports":["import os"]}'
BADPATCH = '{"start_line":3,"end_line":3,"replacement":"  el.innerHTML = name + 1;","imports":[]}'
MODE = {"patch": PATCH}


class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        text = LEAD if "Return a JSON array" in body else VERDICT if "Scanner finding:" in body else MODE["patch"]
        data = json.dumps({"content": [{"type": "text", "text": text}]}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)


def rules(name, code):
    return [(f.cwe, f.line, f.severity) for f in static_analysis.run([SourceFile(name, code)], [])]


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start(); cls.url = f"http://127.0.0.1:{cls.srv.server_port}"

    @classmethod
    def tearDownClass(cls): cls.srv.shutdown()

    def setUp(self):
        for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "LLM_PROVIDER"): os.environ.pop(k, None)
        os.environ["LLM_CACHE"] = os.path.join(tempfile.mkdtemp(), "c.json"); os.environ["ML_MODEL"] = os.path.join(tempfile.mkdtemp(), "n.json")

    def test_rule_scanners_without_any_key(self):
        self.assertEqual(rules("a.js", JS), [("CWE-79", 3, "high")])
        self.assertEqual(rules("a.html", HTML), [("CWE-79", 3, "high")])
        self.assertEqual(rules("A.java", JAVA), [("CWE-89", 3, "high"), ("CWE-78", 4, "high")])
        self.assertEqual(rules("a.js", "el.innerHTML = 'static text';\nconst x = 1;"), [])      # a literal is not flagged

    @unittest.skipUnless(HAVE_FF, "flawfinder not installed")
    def test_c_uses_flawfinder(self):
        r = static_analysis.run([SourceFile("src/a.c", C)], [])
        self.assertTrue(r and r[0].line == 4 and r[0].severity == "high" and r[0].signals.static.note.startswith("Rule FF-"))

    def test_python_and_js_in_one_scan(self):
        r = static_analysis.run([SourceFile("a.py", "import hashlib\nhashlib.md5(b'x')\n"), SourceFile("b.js", JS)], [])
        self.assertEqual(sorted(f.file for f in r), ["a.py", "b.js"])

    def test_js_full_flow_with_llm(self):
        os.environ.update(ANTHROPIC_API_KEY="k", ANTHROPIC_BASE_URL=self.url); MODE["patch"] = PATCH
        files, notes = collect(ScanRequest(source="paste", filename="web/app.js", code=JS))
        r = run_pipeline(files, notes)
        by = {f.line: f for f in r.findings}
        self.assertEqual(sorted(by), [1, 3])                           # line 3 once (rule, not duplicated), line 99 dropped
        rule, lead = by[3], by[1]
        self.assertTrue(rule.signals.static.hit and rule.signals.llm.verdict == "exploitable")
        self.assertEqual((rule.fix.verified, rule.fix.attempts), (True, 1))      # the rule no longer fires on the patched line
        self.assertEqual((rule.consistency.runs, rule.consistency.same), (3, 3))  # the rename test now runs on JavaScript too
        self.assertNotIn("import os", " ".join(rule.fix.patch))
        self.assertEqual((lead.signals.static.note, lead.fix.verified), ("LLM review", False))   # an LLM-only lead is never 'verified'

    def test_bad_js_patch_is_rejected(self):
        os.environ.update(ANTHROPIC_API_KEY="k", ANTHROPIC_BASE_URL=self.url); MODE["patch"] = BADPATCH
        files, notes = collect(ScanRequest(source="paste", filename="web/app.js", code=JS))
        f = next(x for x in run_pipeline(files, notes).findings if x.line == 3)
        self.assertEqual((f.fix.verified, f.fix.attempts), (False, 3))


class Warn(unittest.TestCase):
    def test_unknown_extension_warns_instead_of_looking_safe(self):
        _, notes = collect(ScanRequest(source="paste", filename="main.go", code="package main\nfunc main() {}\n"))
        self.assertTrue(notes and "does NOT mean" in notes[0])
        self.assertEqual(collect(ScanRequest(source="paste", filename="a.js", code="var a=1"))[1], [])


if __name__ == "__main__":
    unittest.main()
