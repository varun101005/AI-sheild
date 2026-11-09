"""Tests for the rename test: the renamer itself, then the stage against a fake LLM server."""
import ast, os, sys, tempfile, threading, unittest
from http.server import HTTPServer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_llm_stage import CALLS, CODE, MODE, Fake
from app.inputs import collect
from app.pipeline import run_pipeline
from app.schemas import ScanRequest
from app.stages.consistency import _variants

SRC = '''import os
API_KEY = "sk-live-123456"
def login(user, pw):
    q = "SELECT * FROM t WHERE a='" + pw + "'"
    print(f"user {user}")
    return db.execute(q, timeout=5)
def ping(host):
    os.system("ping -c 1 " + host)
'''


class Rename(unittest.TestCase):
    def test_variants(self):
        vs = _variants(SRC)
        self.assertEqual(len(vs), 2)
        for v in vs:
            text = "\n".join(v)
            ast.parse(text)                                   # still valid Python
            self.assertEqual(len(v), len(SRC.split("\n")))    # line numbers unchanged
            for gone in ("API_KEY", "host", "pw", "q ="): self.assertNotIn(gone, text)
            for kept in ("os.system", "timeout=5", "def login", "print(f\"user {user}\")", "db.execute"): self.assertIn(kept, text)
        self.assertNotEqual(vs[0], vs[1])

    def test_unparsable_or_nothing_to_rename(self):
        self.assertEqual(_variants("def (:"), [])
        self.assertEqual(_variants("print('hi')\n"), [])


class Live(unittest.TestCase):
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
        MODE["m"] = "ok"; CALLS.clear()

    def scan(self):
        files, notes = collect(ScanRequest(source="paste", filename="a.py", code=CODE))
        return run_pipeline(files, notes)

    def cmd(self, r): return next(f for f in r.findings if f.cwe == "CWE-78")

    def test_stable_verdict(self):
        os.environ.update(ANTHROPIC_API_KEY="k", ANTHROPIC_BASE_URL=self.url)
        c = self.cmd(self.scan()).consistency
        self.assertEqual((c.runs, c.same), (3, 3))

    def test_flipping_verdict_is_detected(self):
        os.environ.update(ANTHROPIC_API_KEY="k", ANTHROPIC_BASE_URL=self.url); MODE["m"] = "rename"
        r = self.scan(); c = self.cmd(r).consistency
        self.assertEqual((c.runs, c.same), (3, 1))
        self.assertLess(self.cmd(r).confidence, 0.84)
        self.assertNotIn("llm_checked", r.model_dump())
        self.assertNotIn("llm_checked", r.model_dump()["findings"][0])

    def test_no_key_means_no_fake_numbers(self):
        c = self.cmd(self.scan()).consistency
        self.assertEqual((c.runs, c.same), (0, 0))


if __name__ == "__main__":
    unittest.main()
