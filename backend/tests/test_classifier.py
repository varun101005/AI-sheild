"""Classifier tests. The synthetic data only proves the plumbing works, it says nothing about real accuracy."""
import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.classifier_model import features, load_model, score, unit_for
from app.inputs import SourceFile
from app.schemas import Clf, Finding, LLM, Signals
from app.stages import integration, ml_classifier

try:
    import sklearn  # noqa: F401
    HAVE_SK = True
except ImportError:
    HAVE_SK = False


def rows(n, start=0):
    out = []
    for i in range(start, start + n):
        out.append({"label": 1, "code": f"def f{i}(user{i}):\n    q = 'SELECT * FROM t WHERE n=' + user{i}\n    return db.execute(q)"})
        out.append({"label": 0, "code": f"def f{i}(user{i}):\n    q = 'SELECT * FROM t WHERE n=?'\n    return db.execute(q, (user{i},))"})
    return out


class T(unittest.TestCase):
    def setUp(self):
        os.environ.pop("ML_MODEL", None)

    def test_unit_for(self):
        src = "X = 1\n\ndef a():\n    return 1\n\ndef b(p):\n    q = p + 1\n    return q\n"
        self.assertIn("def b(p)", unit_for(src, 7)); self.assertNotIn("def a", unit_for(src, 7))
        self.assertIn("X = 1", unit_for(src, 1))                      # module level -> window
        self.assertTrue(unit_for("def (:", 1))                        # unparsable -> window, no crash

    def test_no_model_means_no_signal_and_no_dismissal(self):
        os.environ["ML_MODEL"] = os.path.join(tempfile.mkdtemp(), "missing.json")
        f = Finding(id="F-1", file="a.py", line=1, cwe="CWE-89", type="x", severity="high",
                    signals=Signals(llm=LLM(verdict="not exploitable", score=0.1)))
        ml_classifier.run([SourceFile("a.py", "x=1")], [f])
        self.assertIsNone(f.signals.clf.score); self.assertIn("no trained model", ml_classifier.STATUS)
        integration.run([], [f]); self.assertEqual(f.reason, "")      # one signal alone never dismisses
        f.signals.clf = Clf(score=0.1); integration.run([], [f]); self.assertNotEqual(f.reason, "")

    @unittest.skipUnless(HAVE_SK, "scikit-learn not installed")
    def test_train_export_parity_and_stage(self):
        from ml.train_classifier import metrics, train_model
        model, vec, clf, rep = train_model(rows(40), rows(10, 100))
        for r in rows(5, 200):                                         # pure-Python score == scikit-learn score
            want = clf.predict_proba(vec.transform([r["code"]]))[:, 1][0]
            self.assertAlmostEqual(score(model, r["code"]), want, places=6)
        self.assertGreater(rep["val_at_chosen_threshold"]["f1"], 0.9)  # trivially separable synthetic data
        path = os.path.join(tempfile.mkdtemp(), "m.json"); json.dump(model, open(path, "w"))
        os.environ["ML_MODEL"] = path
        vuln = "def g(u):\n    q = 'SELECT * FROM t WHERE n=' + u\n    return db.execute(q)\n"
        safe = "def g(u):\n    q = 'SELECT * FROM t WHERE n=?'\n    return db.execute(q, (u,))\n"
        fa = Finding(id="F-1", file="v.py", line=2, cwe="CWE-89", type="x", severity="high")
        fb = Finding(id="F-2", file="s.py", line=2, cwe="CWE-89", type="x", severity="high")
        ml_classifier.run([SourceFile("v.py", vuln), SourceFile("s.py", safe)], [fa, fb])
        self.assertGreater(fa.signals.clf.score, fb.signals.clf.score); self.assertIn("live", ml_classifier.STATUS)
        self.assertEqual(metrics([1, 0, 1, 0], [0.9, 0.8, 0.2, 0.1], 0.5)["tp"], 1)


class Languages(unittest.TestCase):
    def test_c_style_comments_and_units(self):
        from app.classifier_model import prep
        self.assertEqual(prep("#include <x.h>\nint a; // note\n/* block */ int b;", "c_cpp"), "#include <x.h>\nint a;\n  int b;")
        java = "class A {\n  int g() {\n    return 1;\n  }\n  void f(String u) {\n    run(\"x\" + u);\n  }\n}\n"
        u = unit_for(java, 6, lang="java"); self.assertIn("void f(String u)", u); self.assertNotIn("int g()", u)
        self.assertTrue(unit_for("int main()\n{\n  gets(buf);\n}\n", 3, lang="c_cpp").startswith("int main()"))   # brace on its own line

    @unittest.skipUnless(HAVE_SK, "scikit-learn not installed")
    def test_one_model_per_language(self):
        from ml.train_classifier import train_model
        jrows = [{"label": l, "code": ("void f%d(String u) {\n  stmt.executeQuery(\"SELECT \" + u);\n}" if l else "void f%d(String u) {\n  stmt.setString(1, u);\n}") % i}
                 for i in range(40) for l in (1, 0)]
        model, *_ = train_model(jrows, jrows[:30], "java"); self.assertEqual(model["lang"], "java")
        d = tempfile.mkdtemp(); json.dump(model, open(os.path.join(d, "classifier_java.json"), "w"))
        os.environ["ML_MODEL_DIR"] = d; os.environ["ML_MODEL"] = os.path.join(d, "no_python_model.json")
        try:
            fj = Finding(id="F-1", file="A.java", line=2, cwe="CWE-89", type="x", severity="high")
            fp = Finding(id="F-2", file="a.py", line=1, cwe="CWE-89", type="x", severity="high")
            src = "class A {\n  void f(String u) {\n    stmt.executeQuery(\"SELECT \" + u);\n  }\n}\n"
            ml_classifier.run([SourceFile("A.java", src), SourceFile("a.py", "x = 1\n")], [fj, fp])
            self.assertGreater(fj.signals.clf.score, 0.5); self.assertIsNone(fp.signals.clf.score)
            self.assertIn("java: trained on 80 methods", ml_classifier.STATUS); self.assertIn("no model for python", ml_classifier.STATUS)
        finally:
            os.environ.pop("ML_MODEL_DIR", None)


if __name__ == "__main__":
    unittest.main()
