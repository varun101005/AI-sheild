"""Runs the dataset builder on a tiny fake CVEfixes database (same table and column names as the real one)."""
import gzip, json, os, sqlite3, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.prepare_dataset import build_db, prepare

SCHEMA = """
CREATE TABLE fixes (cve_id TEXT, hash TEXT, repo_url TEXT);
CREATE TABLE file_change (file_change_id INTEGER, hash TEXT, filename TEXT);
CREATE TABLE method_change (method_change_id INTEGER, file_change_id INTEGER, name TEXT, code TEXT, before_change TEXT);
CREATE TABLE cwe_classification (cve_id TEXT, cwe_id TEXT);
"""


def make_db(path):
    con = sqlite3.connect(path); con.executescript(SCHEMA)
    mid = 0
    def add(fid, name, code, before):
        nonlocal mid; mid += 1
        con.execute("INSERT INTO method_change VALUES (?,?,?,?,?)", (mid, fid, name, code, before))
    for i in range(40):                                    # 40 repos, one vulnerable + one fixed method each
        con.execute("INSERT INTO fixes VALUES (?,?,?)", (f"CVE-{i}", f"h{i}", f"https://github.com/o/r{i}"))
        con.execute("INSERT INTO file_change VALUES (?,?,?)", (i, f"h{i}", f"app/m{i}.py"))
        con.execute("INSERT INTO cwe_classification VALUES (?,?)", (f"CVE-{i}", "CWE-89"))
        add(i, "q", f"def q{i}(x):\n    return db.execute('SELECT * FROM t WHERE a=' + x)  # {i}", "True")
        add(i, "q", f"def q{i}(x):\n    return db.execute('SELECT * FROM t WHERE a=?', (x,))  # {i}", "False")
    con.execute("INSERT INTO file_change VALUES (100,'h0','lib/x.js')")        # not Python: dropped
    add(100, "js", "function f(x){ return eval(x) + 1 + 2 + 3 + 4 + 5 + 6; }", "True")
    add(0, "tiny", "def a(): pass", "True")                                     # too short: dropped
    add(0, "both1", "def same(x):\n    return x + 1 + 2 + 3 + 4 + 5 + 6 + 7", "True")   # same code, both labels: dropped
    add(0, "both2", "def same(x):\n    return x + 1 + 2 + 3 + 4 + 5 + 6 + 7", "False")
    add(0, "dup", "def q0(x):\n    return db.execute('SELECT * FROM t WHERE a=' + x)  # 0", "True")  # duplicate: kept once
    con.commit(); con.close()


class T(unittest.TestCase):
    def test_prepare(self):
        d = tempfile.mkdtemp(); db = os.path.join(d, "c.db"); make_db(db)
        st = prepare(db, os.path.join(d, "out"))
        self.assertEqual(st["dropped_conflicting_labels"], 1)
        total = sum(v["vulnerable"] + v["fixed"] for v in st["splits"].values())
        self.assertEqual(total, 80)                        # 40 vulnerable + 40 fixed, nothing else survived
        repos = {}
        for s in ("train", "val", "test"):
            for line in open(os.path.join(d, "out", f"{s}.jsonl")):
                r = json.loads(line); repos.setdefault(r["repo"], set()).add(s)
                self.assertEqual(r["cwe"], ["CWE-89"])
        self.assertTrue(all(len(v) == 1 for v in repos.values()), "a repo appears in two splits")
        self.assertGreater(len(st["splits"]["train"]), 0)

    def test_build_db_from_dump(self):
        d = tempfile.mkdtemp(); gz = os.path.join(d, "c.sql.gz")
        with gzip.open(gz, "wt") as f:
            f.write("CREATE TABLE t (a TEXT);\nINSERT INTO t VALUES ('x;\ny');\nINSERT INTO t VALUES ('z');\n")
        build_db(gz, os.path.join(d, "c.db"))
        self.assertEqual(sqlite3.connect(os.path.join(d, "c.db")).execute("SELECT count(*) FROM t").fetchone()[0], 2)

    def test_missing_column_is_explained(self):
        d = tempfile.mkdtemp(); db = os.path.join(d, "c.db"); con = sqlite3.connect(db)
        con.executescript(SCHEMA.replace("repo_url TEXT", "other TEXT")); con.close()
        with self.assertRaises(SystemExit): prepare(db, os.path.join(d, "o"))


if __name__ == "__main__":
    unittest.main()
