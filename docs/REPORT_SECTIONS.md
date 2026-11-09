# Text for the report (fill the blanks only with numbers you measured)

## Proposed Novel Contributions
CodeShieldAI does not propose a new learning algorithm. Its contributions are:
1. **Cross-checked triage.** A rule scanner (Bandit), an LLM reviewer and a trained classifier each judge every finding. An integration
   layer merges them (confidence = 0.2 static + 0.5 LLM + 0.3 classifier, scaled by rename-test agreement) and dismisses a finding
   only when the LLM and the classifier both say it is not a real problem.
2. **Rename-consistency check.** The LLM is asked the same question again on copies of the code with the variable names changed.
   A verdict that changes means the model reacted to naming, not logic, so confidence drops.
3. **Verify-and-repair loop.** A proposed patch is accepted only if the file still parses, Bandit no longer reports the original rule
   on the patched lines, no new medium or high finding appears, and the classifier score does not increase. Failures are fed back
   to the LLM (up to 3 attempts); otherwise the fix is marked "needs review". This is a heuristic check, not a proof of correctness.
4. **Leakage-safe evaluation.** CVEfixes Python methods, split by repository, deduplicated, with an ablation of each component.
5. **Application.** A Builder that generates a prototype and runs the same scan-and-repair loop on its Python code.

## Experiment protocol
Data: CVEfixes (Python methods), split by repository 70/15/15, seed 13. Tuning on validation only; test scored once.
| Configuration | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| Static only | ___ | ___ | ___ | ___ |
| Static + LLM | ___ | ___ | ___ | ___ |
| + classifier | ___ | ___ | ___ | ___ |
| Full (+ rename test) | ___ | ___ | ___ | ___ |

Rename test: ___ of ___ findings changed verdict (flip rate ___). Fix verification: ___ verified first try, ___ after retry, ___ not verified of ___.
Classifier baseline: F1 ___ against always-"vulnerable" F1 ___.

## Limitations (keep these in the report)
- JavaScript, TypeScript, Java and HTML use simple built-in regex rules and C/C++ use flawfinder. "Verified" outside Python means only that the rule no longer fires (no syntax or compile check). There is one classifier per language group trained on CVEfixes methods (HTML has no CVEfixes data and shares the JS/TS model), function boundaries outside Python come from a brace heuristic, and the rename test outside Python is a token-based heuristic, not a parser. LLM line numbers can be wrong.
- CVEfixes labels are noisy: a fixing commit also changes methods that were not vulnerable.
- Methods are analysed in isolation, without the rest of the project.
- The classifier is a TF-IDF baseline, and vulnerable and fixed versions often differ by one line.
- The integration weights and the dismissal threshold were set by hand, not tuned.
- Results depend on the LLM chosen; the same scan can differ between models.
- Code is sent to the LLM provider.
