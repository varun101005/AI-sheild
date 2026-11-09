# Viva demo script (about 6 minutes)

Rehearse it three times. Run it against the real backend with your key, not mock mode, and keep a screen recording as backup.

1. **The problem (30 s).** Rule scanners flag too much and explain too little. LLMs explain well but can be fooled by names and
   fixes are rarely checked. We cross-check them and verify fixes.
2. **The pipeline (45 s).** Show the diagram: static analysis, LLM reasoning, classifier, rename test, integration, fix + verify loop.
3. **Live scan (90 s).** Scanner tab, paste the sample, Run. Open a finding: three signals and the agreement dots, the explanation,
   the rename test ("x of 3 runs"), the diff, "Verified after N attempts". Tick "Show dismissed alerts" and open one.
4. **Our two additions (60 s).** Rename test: same question with variable names changed, a verdict that flips loses confidence.
   Verify-and-repair: a patch must parse, remove the original finding, add no new serious finding, and not raise the classifier score.
   Say plainly that this is a heuristic check, not a proof.
5. **Numbers (60 s).** The ablation table (static, + LLM, + classifier, full) and the rename flip rate and fix verification rate.
   Quote only numbers you produced. Name the limits: noisy labels, methods analysed in isolation, Python only.
6. **Builder (60 s).** Builder tab: "a small notes app" as a Python app, 2 repair rounds. Show round 1 vs round 2 findings and the ZIP.
   Websites and slides are scanned too (HTML/JS pattern rules plus LLM review), but only Python gets a trained classifier verdict in the demo unless you train the others.

## Questions to expect
- *What is new?* Not a new learning algorithm. The integration, the rename test, the verified fixes, and a leakage-safe evaluation.
- *Why trust the LLM?* We do not alone: it needs the other signals, and the rename test checks it.
- *What does "verified" mean?* The four checks in step 4. Not a formal proof.
- *What can go wrong?* Label noise in CVEfixes, a weak baseline classifier, the LLM missing context, Bandit missing things
  (it ignored `API_KEY = "sk-live-..."` in our sample), and code leaving the machine to the LLM provider.
- *Why is the test set separate?* The split is by repository, and test numbers are produced once, at the end.
