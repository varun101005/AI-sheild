"""Checks that the ablation harness runs end to end. Numbers from the demo file prove nothing about accuracy."""
import json, os, subprocess, sys, tempfile, unittest
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class T(unittest.TestCase):
    def test_static_only_on_demo_samples(self):
        out, env = tempfile.mkdtemp(), {k: v for k, v in os.environ.items() if "API_KEY" not in k}
        env["ML_MODEL"] = os.path.join(out, "none.json")
        r = subprocess.run([sys.executable, "-m", "benchmarks.run_ablation", "--data", "benchmarks/demo_samples.jsonl", "--out", out],
                           cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        d = json.load(open(os.path.join(out, "ablation.json")))
        t = d["table"]
        self.assertEqual(d["extra"]["samples"], 16); self.assertEqual(d["extra"]["share_vulnerable"], 0.5)
        self.assertIsNone(t["static + LLM"]); self.assertIsNone(t["full (+ rename test)"])
        s = t["static only"]
        self.assertEqual(s["tp"] + s["fp"] + s["tn"] + s["fn"], 16)
        self.assertGreaterEqual(s["recall"], 0.75)                   # Bandit knows these classic patterns
        self.assertTrue(os.path.exists(os.path.join(out, "ablation.md")))


if __name__ == "__main__":
    unittest.main()
