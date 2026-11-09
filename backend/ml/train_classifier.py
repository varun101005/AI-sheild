"""Day 9: train the baseline classifier (TF-IDF + logistic regression) on the Day 8 dataset.

  python -m ml.train_classifier --data ml/data --out ml/model            (train, tune threshold on VAL)
  python -m ml.train_classifier --data ml/data --out ml/model --final    (also score TEST once, for the report)

Run --final only when you are done changing things. Looking at test numbers and then tweaking = cheating yourself."""
import argparse
import functools
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.classifier_model import features  # noqa: E402


def load(path):
    return [json.loads(l) for l in open(path, encoding="utf-8")]


def metrics(y, p, t):
    pred = [int(x >= t) for x in p]
    tp = sum(a == 1 and b == 1 for a, b in zip(y, pred)); fp = sum(a == 0 and b == 1 for a, b in zip(y, pred))
    tn = sum(a == 0 and b == 0 for a, b in zip(y, pred)); fn = sum(a == 1 and b == 0 for a, b in zip(y, pred))
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {"threshold": round(t, 2), "precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0,
            "fpr": round(fp / (fp + tn), 4) if fp + tn else 0.0, "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def train_model(train, val, lang="python"):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import roc_auc_score
    ytr, yva = [r["label"] for r in train], [r["label"] for r in val]
    if len(set(ytr)) < 2 or len(set(yva)) < 2:
        raise SystemExit("train and val must each contain both labels")
    vec = TfidfVectorizer(analyzer=functools.partial(features, lang=lang), sublinear_tf=True, min_df=2, max_features=50000)
    clf = LogisticRegression(class_weight="balanced", max_iter=2000)
    clf.fit(vec.fit_transform([r["code"] for r in train]), ytr)
    pva = clf.predict_proba(vec.transform([r["code"] for r in val]))[:, 1]
    t = max((i / 100 for i in range(5, 96)), key=lambda t: metrics(yva, pva, t)["f1"])
    model = {"name": "tfidf-logreg", "version": 1, "lang": lang, "intercept": float(clf.intercept_[0]), "threshold": round(t, 2),
             "n_train": len(train),
             "features": {tok: [float(vec.idf_[i]), float(clf.coef_[0][i])] for tok, i in vec.vocabulary_.items()}}
    rep = {"val_at_chosen_threshold": metrics(yva, pva, t), "val_at_0.5": metrics(yva, pva, 0.5),
           "val_auc": round(float(roc_auc_score(yva, pva)), 4), "val_share_vulnerable": round(sum(yva) / len(yva), 4)}
    return model, vec, clf, rep


GROUPS = ["python", "c_cpp", "java", "js_ts"]

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="ml/data"); ap.add_argument("--out", default="ml/model")
    ap.add_argument("--lang", default="python", help="python, c_cpp, java, js_ts or all")
    ap.add_argument("--final", action="store_true")
    a = ap.parse_args()
    from app.classifier_model import score
    for lang in (GROUPS if a.lang == "all" else [a.lang]):
        d, out = Path(a.data) / lang, Path(a.out)
        if not (d / "train.jsonl").exists():
            print(f"[{lang}] no data in {d}, skipped"); continue
        model, vec, clf, rep = train_model(load(d / "train.jsonl"), load(d / "val.jsonl"), lang)
        if a.final:
            te = load(d / "test.jsonl")
            rep["test"] = metrics([r["label"] for r in te], [score(model, r["code"]) for r in te], model["threshold"])
            rep["test_size"] = len(te)
        out.mkdir(parents=True, exist_ok=True)
        (out / f"classifier_{lang}.json").write_text(json.dumps(model), encoding="utf-8")
        (out / f"metrics_{lang}.json").write_text(json.dumps(rep, indent=2), encoding="utf-8")
        print(f"[{lang}]", json.dumps(rep, indent=2))
        print(f"[{lang}] saved {out / f'classifier_{lang}.json'} ({len(model['features'])} features)")
    print("Reminder: near-identical vulnerable/fixed pairs make this task hard. Compare with 'val_share_vulnerable'.")
