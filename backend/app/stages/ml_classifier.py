"""Stage 3: the 'sniffer dog'. Scores the function around each finding with the model for that file's language.
No model for a language -> score stays None (no signal) and integration works without it. We never invent a score."""
from ..classifier_model import lang_of, load_model, score, unit_for
from ..schemas import Clf

STATUS = ""


def run(files, findings):
    global STATUS
    texts, models, used, missing = {f.path: f.text for f in files}, {}, {}, set()
    for f in findings:
        g = lang_of(f.file)
        if g is None:
            continue
        if g not in models:
            models[g] = load_model(g)
        if not models[g]:
            missing.add(g)
            continue
        f.signals.clf = Clf(score=round(score(models[g], unit_for(texts.get(f.file, ""), f.line, lang=g)), 2))
        used[g] = models[g]
    if used:
        STATUS = "live (" + "; ".join(f"{g}: trained on {m['n_train']} methods" for g, m in used.items()) + ")" \
                 + (f"; no model for {', '.join(sorted(missing))}" if missing else "")
    else:
        STATUS = "no trained model found (run ml/train_classifier.py), so there is no classifier signal" if missing else ""
    return findings
