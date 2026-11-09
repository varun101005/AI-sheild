# CodeShieldAI backend

## Run
```
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
Then open `dashboard/index.html`, set `useMock:false` in its `CFG`, and run a scan.
Docs and a try-it page: http://localhost:8000/docs

## Pipeline (app/pipeline.py)
Each stage is a file in `app/stages/` with `run(files, findings) -> findings`. The contract is `app/schemas.py`.

| Stage file | Day | Status |
|---|---|---|
| static_analysis.py | 5 | REAL: runs Bandit (Python only) |
| llm_reasoning.py | 6 | REAL: LLM verdict + explanation per finding (needs an API key) |
| consistency.py | 7 | REAL: rename test, re-asks the LLM with renamed variables (our idea 1) |
| ml_classifier.py | 8-9 | REAL once you train a model (ml/train_classifier.py), otherwise no signal |
| integration.py | 10 | v0 merge rule, real code, still to tune |
| fix_engine.py | 11-12 | placeholder, our idea 2 (verify loop) |

Rule for teammates: do not change `schemas.py` alone. Agree on the change first.
Results are not real analysis until the placeholders are replaced.

## LLM setup (Day 6)
1. Copy `.env.example` to `.env` and fill in ONE key. Never commit `.env` (it is in `.gitignore`).
2. Anthropic: `ANTHROPIC_API_KEY`. OpenAI-compatible (OpenAI, Groq, Ollama, Gemini): `OPENAI_API_KEY`, plus `OPENAI_BASE_URL` and `LLM_MODEL` for non-OpenAI providers.
3. Without a key the pipeline still runs, but every finding says the LLM is not configured.
4. Privacy: the code around each finding is sent to the provider you choose. Do not scan code you may not share.
5. Answers are cached in `.llm_cache.json`, so re-scans of the same code cost nothing.
6. Tests (no real API needed, they use a fake local server): `python -m unittest discover -s tests`

## Classifier dataset (Day 8)
1. Download CVEfixes from Zenodo (DOI 10.5281/zenodo.4476563). Unzip until you find `CVEfixes.sql.gz` (check the Zenodo page for the exact file name and size).
2. First run, builds the database from the dump (slow, one time):
   `python ml/prepare_dataset.py --sql-gz CVEfixes.sql.gz --db CVEfixes.db --out ml/data`
3. Later runs: `python ml/prepare_dataset.py --db CVEfixes.db --out ml/data`
4. Output: `ml/data/<language>/train.jsonl`, `val.jsonl`, `test.jsonl` and `stats.json`. Use `--lang python|c_cpp|java|js_ts|all` (default python). Label 1 = vulnerable method, 0 = the fixed version.
5. The split is by repository. The test split is for the final numbers only, never for tuning.
6. Known weakness: a fixing commit also changes methods that are not the vulnerable one, so some labels are noisy. State this in the report.

## Train the classifier (Day 9)
Needs `pip install -r requirements-ml.txt` and the Day 8 data in `ml/data`.
1. `python -m ml.train_classifier --data ml/data --out ml/model` trains on `train.jsonl`, picks the threshold on `val.jsonl`.
2. It writes `ml/model/classifier.json` (plain JSON, loaded by the backend without scikit-learn) and `ml/model/metrics.json`.
3. Restart the backend. The scan notes then say "ML classifier: live (...)".
4. When finished tuning, run once with `--final` to get the test numbers for the report.
5. Without a model the backend still runs: the classifier shows "not available" and cannot dismiss findings.
6. Compare every number with `val_share_vulnerable` (the score of always guessing "vulnerable"). A baseline that barely beats it is a result worth reporting honestly.

## Languages (Day 9 extended)
One classifier per language group, trained from the same CVEfixes database: `--lang all` builds `ml/data/{python,c_cpp,java,js_ts}`
and `python -m ml.train_classifier --lang all` writes `ml/model/classifier_<group>.json`. HTML has no method-level data in CVEfixes,
so HTML files use the js_ts model. A language without a model simply has no classifier signal. The rename test works for every
supported language (a token-based heuristic outside Python).
