"""Integration layer. v0 merge rule, the main design choice to tune and justify.
confidence = (0.2*static + 0.5*llm + 0.3*classifier) scaled by rename-test agreement.
If the classifier has no score, the other two weights are rescaled and the finding can never be dismissed.
A finding is dismissed when the LLM says not exploitable AND the classifier score is below 0.3."""
W_STATIC, W_LLM, W_CLF = 0.2, 0.5, 0.3


def run(files, findings):
    for f in findings:
        s, c = f.signals, f.consistency
        llm = s.llm.score if s.llm.verdict == "exploitable" else 0.0
        static = 1.0 if s.static.hit else 0.0
        if s.clf.score is None:
            base = (W_STATIC * static + W_LLM * llm) / (W_STATIC + W_LLM)
        else:
            base = W_STATIC * static + W_LLM * llm + W_CLF * s.clf.score
        agree = c.same / c.runs if c.runs else 1.0
        f.confidence = round(base * (0.5 + 0.5 * agree), 2)
        if s.llm.verdict == "not exploitable" and s.clf.score is not None and s.clf.score < 0.3:
            f.reason = "The LLM judged it not exploitable and the classifier score is low."
            f.explanation = ""
    return findings
