"""Builder against a fake LLM server: generate, scan, ask for fixes, rescan, zip."""
import base64, io, json, os, sys, tempfile, threading, unittest, zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.builder import BuildError, BuildRequest, build, parse_files

BAD = ('=== FILE: app.py ===\nfrom flask import Flask\napp = Flask(__name__)\n@app.route("/")\ndef index():\n    return "hi"\n'
       'if __name__ == "__main__":\n    app.run(debug=True)\n=== END FILE ===\n'
       '=== FILE: ../evil.py ===\nx=1\n=== END FILE ===\n=== FILE: run.exe ===\nzz\n=== END FILE ===\n'
       '=== FILE: templates/index.html ===\n<h1>hi</h1>\n=== END FILE ===')
FIXED = BAD.replace("app.run(debug=True)", "app.run()")
SITE = "=== FILE: index.html ===\n<h1>site</h1>\n=== END FILE ==="
CALLS = []


class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode(); CALLS.append(1)
        if "Scanner finding:" in body:
            text = '{"verdict":"exploitable","score":0.9,"explanation":"Debug mode exposes a console."}'
        elif "A security scan found" in body:
            text = FIXED
        else:
            text = SITE if "website" in body or "slide" in body.lower() else BAD
        data = json.dumps({"content": [{"type": "text", "text": text}]}).encode()
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

    def live(self): os.environ.update(ANTHROPIC_API_KEY="k", ANTHROPIC_BASE_URL=self.url)

    def test_parse_drops_unsafe_files(self):
        self.assertEqual(sorted(parse_files(BAD)), ["app.py", "templates/index.html"])

    def test_app_is_scanned_repaired_and_zipped(self):
        self.live()
        r = build(BuildRequest(prompt="a tiny notes app", kind="app", rounds=2))
        self.assertEqual([h.round for h in r.history], [1, 2])
        self.assertGreaterEqual(r.history[0].high, 1); self.assertEqual(r.history[1].high, 0)
        self.assertIn("app.run()", next(f.content for f in r.files if f.path == "app.py"))
        z = zipfile.ZipFile(io.BytesIO(base64.b64decode(r.zip_b64)))
        self.assertEqual(sorted(z.namelist()), ["app.py", "templates/index.html"])

    def test_zero_rounds_scans_once(self):
        self.live(); r = build(BuildRequest(prompt="a tiny notes app", kind="app", rounds=0))
        self.assertEqual(len(r.history), 1); self.assertTrue(any("remain" in n for n in r.notes))

    def test_website_is_scanned_too(self):
        self.live(); r = build(BuildRequest(prompt="a portfolio website", kind="website"))
        self.assertEqual((len(r.history), r.history[0].findings), (1, 0))

    def test_no_key_is_a_clear_error(self):
        with self.assertRaises(BuildError) as c: build(BuildRequest(prompt="a tiny notes app", kind="app"))
        self.assertEqual(c.exception.status, 503)


if __name__ == "__main__":
    unittest.main()
