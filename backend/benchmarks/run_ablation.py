"""Ablation benchmark (Day 14-15): what does each part of the pipeline add?

  python -m benchmarks.run_ablation --data ml/data/test.jsonl --limit 200 --out benchmarks/results
  python -m benchmarks.run_ablation --data benchmarks/demo_samples.jsonl     (16 hand-written samples, a demo, NOT a research benchmark)

A sample counts as "flagged" by a configuration when:
  static only          Bandit reports at least one finding
  + LLM                ... and the LLM calls at least one of them exploitable
  + classifier         ... and the classifier score is at or above the model's validation threshold
  full (+ rename test) ... and the LLM verdict survives the rename test in at least 2 of 3 runs
Needs an LLM key for rows 2-4 and a trained model (ml/model/classifier.json) for rows 3-4.
Use the TEST split once, at the end. Tuning on it makes the numbers meaningless."""
import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.classifier_model import load_model  # noqa: E402
from app.inputs import SourceFile  # noqa: E402
from app.llm_client import config  # noqa: E402
from app.stages import consistency, fix_engine, llm_reasoning, ml_classifier, static_analysis  # noqa: E402
from ml.train_classifier import metrics  # noqa: E402

EXT = {"python": ".py", "c_cpp": ".c", "java": ".java", "js_ts": ".js"}
NAMES = {"static": "static only", "llm": "static + LLM", "clf": "+ classifier", "full": "full (+ rename test)"}


def analyze(code, live, model, ext=".py"):
    files = [SourceFile("sample" + ext, code)]
    fs = static_analysis.run(files, [])
    out = {"static": bool(fs), "llm": False, "clf": False, "full": False, "tested": 0, "unstable": 0, "files": files, "findings": fs}
    if not fs or not live:
        return out
    llm_reasoning.run(files, fs); ml_classifier.run(files, fs); consistency.run(files, fs)
    for f in fs:
        ex = f.signals.llm.verdict == "exploitable"
        ok = bool(model) and f.signals.clf.score is not None and f.signals.clf.score >= model["threshold"]
        c = f.consistency
        stable = c.runs == 0 or c.same / c.runs >= 2 / 3
        if c.runs:
            out["tested"] += 1
            out["unstable"] += c.same < c.runs
        out["llm"] |= ex; out["clf"] |= ex and ok; out["full"] |= ex and ok and stable
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True); ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--fix-limit", type=int, default=20); ap.add_argument("--seed", type=int, default=13)
    ap.add_argument("--out", default="benchmarks/results"); ap.add_argument("--lang", default="python", help="python, c_cpp, java or js_ts")
    a = ap.parse_args()
    rows = [json.loads(l) for l in open(a.data, encoding="utf-8")]
    random.Random(a.seed).shuffle(rows)
    rows = rows[:a.limit]
    live, model = bool(config()), load_model(a.lang)
    if not live:
        print("No LLM key: only the 'static only' row can be computed.")
    if live and not model:
        print("No trained model: the classifier rows will be n/a.")
    y, preds, tested, unstable, fix_pool = [], {k: [] for k in NAMES}, 0, 0, []
    for i, r in enumerate(rows, 1):
        res = analyze(r["code"], live, model, EXT[a.lang])
        y.append(r["label"])
        for k in NAMES:
            preds[k].append(int(res[k]))
        tested += res["tested"]; unstable += res["unstable"]
        if r["label"] == 1 and res["llm"]:
            fix_pool.append(res)
        if i % 10 == 0:
            print(f"  {i}/{len(rows)} samples")
    table = {}
    for k, name in NAMES.items():
        if k == "static" or (k == "llm" and live) or (k in ("clf", "full") and live and model):
            table[name] = metrics(y, preds[k], 0.5)
        else:
            table[name] = None
    extra = {"samples": len(rows), "share_vulnerable": round(sum(y) / max(1, len(y)), 3),
             "rename_test": {"findings_tested": tested, "verdict_flipped": unstable,
                             "flip_rate": round(unstable / tested, 3) if tested else None}}
    if live and fix_pool:
        v1 = vl = 0
        pool = fix_pool[:a.fix_limit]
        for res in pool:
            fix_engine.run(res["files"], res["findings"])
            for f in res["findings"]:
                v1 += f.fix.verified and f.fix.attempts == 1
                vl += f.fix.verified and f.fix.attempts > 1
        n = sum(len(r["findings"]) for r in pool)
        extra["fix_verification"] = {"findings_with_fix_attempt": n, "verified_first_try": v1, "verified_after_retry": vl,
                                     "not_verified": n - v1 - vl}
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    (out / "ablation.json").write_text(json.dumps({"table": table, "extra": extra}, indent=2), encoding="utf-8")
    md = ["| Configuration | Precision | Recall | F1 | False-positive rate | TP | FP | TN | FN |", "|---|---|---|---|---|---|---|---|---|"]
    for name, m in table.items():
        md.append(f"| {name} | " + (" | ".join(str(m[k]) for k in ("precision", "recall", "f1", "fpr", "tp", "fp", "tn", "fn")) if m else "n/a | " * 7 + "n/a") + " |")
    md += ["", f"Samples: {extra['samples']} (share vulnerable: {extra['share_vulnerable']}). Data: {a.data}.",
           f"Rename test: {json.dumps(extra['rename_test'])}", f"Fix verification: {json.dumps(extra.get('fix_verification', 'not run'))}",
           "", "Caveats: samples are single methods analysed in isolation, labels from fix commits are noisy, and a result is only as good as the split it came from."]
    (out / "ablation.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))


if __name__ == "__main__":
    main()
