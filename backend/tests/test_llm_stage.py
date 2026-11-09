"""Tests the LLM stage against a fake local server, so no API key or internet is needed."""
import json, os, sys, tempfile, threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.inputs import collect
from app.pipeline import run_pipeline
from app.schemas import ScanRequest

CODE = "import os, pickle\ndef ping(host):\n    os.system('ping -c 1 ' + host)\n"
CALLS, MODE = [], {"m": "ok"}


class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        CALLS.append(self.path)
        if MODE["m"] == "garbage":
            text = "sorry, no json"
        elif MODE["m"] == "rename" and "CWE-502" not in body:
            text = '{"verdict":"%s","score":0.9,"explanation":"x"}' % ("exploitable" if "host" in body else "not exploitable")
        elif "CWE-502" in body:
            text = '```json\n{"verdict":"not exploitable","score":0.1,"explanation":"Only an import."}\n```'
        else:
            text = '{"verdict":"exploitable","score":0.9,"cwe":"CWE-78","explanation":"Host is joined into a shell command."}'
        out = ({"content": [{"type": "text", "text": text}]} if self.path == "/v1/messages"
               else {"choices": [{"message": {"content": text}}]})
        data = json.dumps(out).encode()
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
        for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "LLM_PROVIDER", "LLM_MODEL"): os.environ.pop(k, None)
        os.environ["LLM_CACHE"] = os.path.join(tempfile.mkdtemp(), "c.json")
        MODE["m"] = "ok"; CALLS.clear()

    def scan(self):
        files, notes = collect(ScanRequest(source="paste", filename="a.py", code=CODE))
        return run_pipeline(files, notes)

    def test_anthropic_and_cache(self):
        os.environ.update(ANTHROPIC_API_KEY="k", ANTHROPIC_BASE_URL=self.url)
        r = self.scan(); n = len(CALLS)
        verdicts = {f.signals.llm.verdict for f in r.findings + r.dismissed}
        self.assertIn("exploitable", verdicts); self.assertIn("not exploitable", verdicts)
        self.assertTrue(any("live (anthropic" in x for x in r.notes))
        self.scan(); self.assertEqual(len(CALLS), n, "second scan must come from cache")

    def test_openai_adapter(self):
        os.environ.update(OPENAI_API_KEY="k", OPENAI_BASE_URL=self.url)
        r = self.scan()
        self.assertTrue(all(p == "/chat/completions" for p in CALLS) and CALLS)
        self.assertTrue(any("live (openai" in x for x in r.notes))

    def test_not_configured(self):
        r = self.scan()
        self.assertEqual({f.signals.llm.verdict for f in r.findings}, {"unsure"})
        self.assertFalse(CALLS); self.assertTrue(any("not configured" in x for x in r.notes))

    def test_garbage_reply_does_not_crash(self):
        os.environ.update(ANTHROPIC_API_KEY="k", ANTHROPIC_BASE_URL=self.url); MODE["m"] = "garbage"
        r = self.scan()
        self.assertTrue(all("failed" in f.explanation for f in r.findings))


if __name__ == "__main__":
    unittest.main()
