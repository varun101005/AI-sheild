"""Verify-and-repair loop against a fake LLM server (no key, no internet)."""
import json, os, sys, tempfile, threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.inputs import SourceFile
from app.stages import fix_engine, static_analysis

CODE = "import os\n\ndef ping(host):\n    os.system('ping -c 1 ' + host)\n"
GOOD = {"start_line": 4, "end_line": 4, "replacement": "    subprocess.run(['ping', '-c', '1', host], check=True)", "imports": ["import subprocess"]}
STILL = {"start_line": 4, "end_line": 4, "replacement": "    os.system('ping -c 1 ' + host)", "imports": []}
SYNTAX = {"start_line": 4, "end_line": 4, "replacement": "    os.system(", "imports": []}
SHELL = {"start_line": 4, "end_line": 4, "replacement": "    subprocess.run('ping ' + host, shell=True)", "imports": ["import subprocess"]}
MODE = {"first": GOOD, "later": GOOD}


class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        reply = MODE["later"] if "previous" in body else MODE["first"]
        data = json.dumps({"content": [{"type": "text", "text": json.dumps(reply)}]}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_port}"

    @classmethod
    def tearDownClass(cls): cls.srv.shutdown()

    def setUp(self):
        for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "LLM_PROVIDER"): os.environ.pop(k, None)
        os.environ["LLM_CACHE"] = os.path.join(tempfile.mkdtemp(), "c.json")
        os.environ["ML_MODEL"] = os.path.join(tempfile.mkdtemp(), "none.json")

    def fix(self, first, later, key=True):
        if key: os.environ.update(ANTHROPIC_API_KEY="k", ANTHROPIC_BASE_URL=self.url)
        MODE.update(first=first, later=later)
        files = [SourceFile("a.py", CODE)]
        fs = static_analysis.run(files, [])
        f = next(x for x in fs if x.cwe == "CWE-78")
        fix_engine.run(files, fs)
        return f.fix

    def test_good_first_try(self):
        fx = self.fix(GOOD, GOOD)
        self.assertEqual((fx.verified, fx.attempts), (True, 1))
        self.assertIn("+ import subprocess", fx.patch); self.assertTrue(fx.patch[0].startswith("- "))

    def test_syntax_error_is_rejected_then_fixed(self):
        fx = self.fix(SYNTAX, GOOD); self.assertEqual((fx.verified, fx.attempts), (True, 2))

    def test_unchanged_vulnerability_is_rejected_then_fixed(self):
        fx = self.fix(STILL, GOOD); self.assertEqual((fx.verified, fx.attempts), (True, 2))

    def test_patch_that_adds_a_new_serious_finding_is_rejected(self):
        fx = self.fix(SHELL, GOOD); self.assertEqual((fx.verified, fx.attempts), (True, 2))

    def test_never_verified_is_honest(self):
        fx = self.fix(STILL, STILL)
        self.assertEqual((fx.verified, fx.attempts), (False, 3)); self.assertTrue(fx.patch)

    def test_no_key_means_no_fix(self):
        fx = self.fix(GOOD, GOOD, key=False)
        self.assertEqual((fx.patch, fx.verified, fx.attempts), ([], False, 0)); self.assertIn("not configured", fix_engine.STATUS)


if __name__ == "__main__":
    unittest.main()
