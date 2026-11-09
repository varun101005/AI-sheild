"""Day 8: build the classifier dataset from CVEfixes (Python methods only).

CVEfixes stores, for every fixing commit, the changed methods twice:
  before_change = 'True'  -> the method as it was BEFORE the fix  (label 1, vulnerable)
  before_change = 'False' -> the method AFTER the fix              (label 0, fixed)

Rules that keep the benchmark honest:
  * the split is by REPOSITORY, so the same project never sits in both train and test
  * identical code is kept once, and code that appears with both labels is dropped
  * the test split is for the final numbers only: never tune on it

Usage:
  python ml/prepare_dataset.py --sql-gz CVEfixes.sql.gz --db CVEfixes.db --out ml/data   (first time, builds the db)
  python ml/prepare_dataset.py --db CVEfixes.db --out ml/data                            (later runs)
"""
import argparse
import collections
import gzip
import hashlib
import json
import sqlite3
from pathlib import Path

NEEDED = {
    "method_change": {"method_change_id", "file_change_id", "name", "code", "before_change"},
    "file_change": {"file_change_id", "hash", "filename"},
    "fixes": {"cve_id", "hash", "repo_url"},
    "cwe_classification": {"cve_id", "cwe_id"},
}
SPLITS = (("train", 70), ("val", 15), ("test", 15))     # percent of repositories
MIN_CHARS, MAX_CHARS = 30, 8000
GROUPS = {"python": (".py",), "c_cpp": (".c", ".h", ".cpp", ".cc", ".hpp"), "java": (".java",), "js_ts": (".js", ".jsx", ".ts", ".tsx")}


def where_for(lang):
    return "(" + " OR ".join(f"lower(fc.filename) LIKE '%{e}'" for e in GROUPS[lang]) + ")"

QUERY = """
SELECT mc.method_change_id, mc.file_change_id, mc.name, mc.code, mc.before_change,
       fx.repo_url, fx.cve_id,
       (SELECT group_concat(cwe_id, ',') FROM cwe_classification WHERE cve_id = fx.cve_id)
FROM method_change mc
JOIN file_change fc ON fc.file_change_id = mc.file_change_id
JOIN fixes fx ON fx.hash = fc.hash
WHERE {where}
"""


def build_db(sql_gz, db_path):
    """Loads the CVEfixes .sql.gz dump into SQLite without needing gzcat or the sqlite3 command (Windows friendly)."""
    con, buf, n = sqlite3.connect(db_path), "", 0
    with gzip.open(sql_gz, "rt", encoding="utf-8", errors="ignore") as f:
        for line in f:
            buf += line
            if sqlite3.complete_statement(buf):
                con.execute(buf)
                buf, n = "", n + 1
                if n % 20000 == 0:
                    print(f"  loaded {n} statements...")
    con.commit()
    con.close()


def check_schema(con):
    for table, cols in NEEDED.items():
        have = {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
        if cols - have:
            raise SystemExit(f"Table '{table}' is missing columns {sorted(cols - have)}. It has: {sorted(have)}")


def split_of(repo, seed):
    bucket, edge = int(hashlib.sha1(f"{seed}:{repo}".encode()).hexdigest(), 16) % 100, 0
    for name, pct in SPLITS:
        edge += pct
        if bucket < edge:
            return name
    return SPLITS[-1][0]


def prepare(db, out, seed=13, lang="python"):
    con = sqlite3.connect(db)
    check_schema(con)
    seen, labels, recs = set(), collections.defaultdict(set), {}
    for mid, fid, name, code, before, repo, cve, cwes in con.execute(QUERY.format(where=where_for(lang))):
        if mid in seen or not code or not (MIN_CHARS <= len(code) <= MAX_CHARS):
            continue
        seen.add(mid)
        label = 1 if str(before).strip().lower() == "true" else 0
        key = hashlib.sha1("".join(code.split()).encode()).hexdigest()
        labels[key].add(label)
        recs.setdefault(key, {"id": str(mid), "pair_id": f"{fid}:{name}", "label": label, "code": code,
                              "cwe": (cwes or "").split(",") if cwes else [], "cve": cve, "repo": repo})
    conflict = [k for k, v in labels.items() if len(v) > 1]
    for k in conflict:
        del recs[k]
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    files = {n: open(out / f"{n}.jsonl", "w", encoding="utf-8") for n, _ in SPLITS}
    stats = {"seed": seed, "dropped_conflicting_labels": len(conflict), "splits": {}}
    repos, cwe_count = collections.defaultdict(set), collections.Counter()
    for r in recs.values():
        s = split_of(r["repo"], seed)
        files[s].write(json.dumps({**r, "split": s}) + "\n")
        repos[s].add(r["repo"])
        stats["splits"].setdefault(s, {"vulnerable": 0, "fixed": 0})["vulnerable" if r["label"] else "fixed"] += 1
        if r["label"]:
            cwe_count.update(r["cwe"])
    for f in files.values():
        f.close()
    names = list(repos)
    assert all(not (repos[a] & repos[b]) for i, a in enumerate(names) for b in names[i + 1:]), "repo leaked across splits"
    for s in repos:
        stats["splits"][s]["repos"] = len(repos[s])
    stats["top_cwes_in_vulnerable"] = cwe_count.most_common(10)
    (out / "stats.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    return stats


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--sql-gz", help="build --db from this CVEfixes dump first")
    ap.add_argument("--out", default="ml/data")
    ap.add_argument("--seed", type=int, default=13)
    ap.add_argument("--lang", default="python", help="python, c_cpp, java, js_ts or all (HTML has no method-level data in CVEfixes)")
    a = ap.parse_args()
    if a.sql_gz:
        print("Building the database (this can take a long time)...")
        build_db(a.sql_gz, a.db)
    for lang in (GROUPS if a.lang == "all" else [a.lang]):
        st = prepare(a.db, Path(a.out) / lang, a.seed, lang)
        print(f"[{lang}]", json.dumps(st, indent=2))
        for name, v in st["splits"].items():
            tot = v["vulnerable"] + v["fixed"]
            if name == "test" and tot < 200:
                print(f"WARNING [{lang}]: the test split has only {tot} methods, so the final numbers will be shaky.")
