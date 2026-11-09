"""Rename test for C, Java and JavaScript: names change, everything else stays."""
import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.stages.consistency import _variants

JS = "const el = document.getElementById('out');\nfunction show(name, opts = {}) {\n  const msg = `hi ${name}`;\n  el.innerHTML = name + msg;\n  return opts.x;\n}\n"
JAVA = 'class A {\n  void f(Statement s, String user) throws Exception {\n    String q = "SELECT * FROM t WHERE a=\'" + user + "\'";\n    s.executeQuery(q);\n  }\n}\n'
C = "#include <string.h>\nvoid f(char *s) {\n  char buf[8];\n  strcpy(buf, s);\n}\n"
TS = "function g(a: string, b: number): void {\n  let tmp: string = a;\n  console.log(tmp, b);\n}\n"


class T(unittest.TestCase):
    def check(self, src, lang, gone, kept):
        vs = _variants(src, lang)
        self.assertEqual(len(vs), 2, "two renamed variants expected")
        for v in vs:
            t = "\n".join(v)
            self.assertEqual(len(v), len(src.split("\n")))               # line numbers unchanged
            for g in gone: self.assertNotIn(g, t)
            for k in kept: self.assertIn(k, t)
        self.assertNotEqual(vs[0], vs[1])

    def test_javascript(self):
        self.check(JS, "js_ts", ["el ", "msg", "opts "], ["document.getElementById('out')", ".innerHTML", "opts.x" if False else ".x;", "`hi ${name}`", "function show(name"])

    def test_java(self):
        self.check(JAVA, "java", ["Statement s", " user", " q ", "(q)"], ["executeQuery", "Statement ", "String ", "throws Exception", "void f("])

    def test_c(self):
        self.check(C, "c_cpp", ["buf", " s)", "(buf, s"], ["#include <string.h>", "strcpy(", "void f(char *"])

    def test_typescript(self):
        self.check(TS, "js_ts", ["tmp", " a:", " b:"], ["console.log", ": string", ": number", "function g("])

    def test_nothing_to_rename_or_unknown_language(self):
        self.assertEqual(_variants("console.log('hi');\n", "js_ts"), [])
        self.assertEqual(_variants("x", None), [])


if __name__ == "__main__":
    unittest.main()
