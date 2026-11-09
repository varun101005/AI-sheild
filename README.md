# CodeShieldAI

Scans Python, JavaScript, TypeScript, Java, C, C++ and HTML code for vulnerabilities by cross-checking three signals (a rule scanner, an LLM and a trained classifier),
filters false alarms, proposes fixes and VERIFIES them before showing them. A Builder tab turns a prompt into a
website, slides or a Flask app, then scans the Python it wrote and asks the AI to fix what the scan finds.

## Run it
- Windows: double-click `start.bat`. Mac/Linux: `./start.sh`. Then open http://localhost:8000
- Put ONE LLM key in `backend/.env` (copy of `.env.example`). Without a key the scanner still runs, but the LLM, rename test,
  fix engine and Builder are off, and the dashboard says so.
- The dashboard opened as a plain file (not through the backend) shows mock data only.

## What is real and what is not
| Part | Status |
|---|---|
| Static analysis (Bandit, Python only) | Real, tested |
| LLM reasoning, rename test, fix + verify loop, Builder | Real code, tested against a FAKE LLM server. Never run against a real provider by the author: try it first |
| ML classifier | One model per language group: python, c_cpp, java, js_ts (HTML shares js_ts, as CVEfixes has no HTML methods). Training and serving code tested on synthetic data. NO trained model is included. Get them: see below |
| Benchmark / ablation | Harness done and tested. NO real results are included. Numbers come from you running it |
| Integration weights (0.2 / 0.5 / 0.3, dismissal rule) | A first guess, not tuned |
| JavaScript, TypeScript, Java, C, C++, HTML | Rule scan (flawfinder for C/C++, simple regex rules for the rest) + LLM review + fix re-check + a classifier per language group + the rename test (both heuristic for non-Python). Never run against a real LLM |

## Get the real numbers (needs your laptop, an LLM key and the CVEfixes download)
1. `cd backend && pip install -r requirements-ml.txt`
2. `python ml/prepare_dataset.py --sql-gz CVEfixes.sql.gz --db CVEfixes.db --out ml/data --lang all`   (see backend/README.md)
3. `python -m ml.train_classifier --data ml/data --out ml/model --lang all`
4. `python -m benchmarks.run_ablation --data ml/data/python/val.jsonl --lang python --limit 200`   (one language at a time: python, c_cpp, java, js_ts. Tune on val, never on test)
5. When you are done changing things: `python -m ml.train_classifier --lang all --final` and `python -m benchmarks.run_ablation --data ml/data/python/test.jsonl --lang python`
6. Copy the tables into the report (docs/REPORT_SECTIONS.md says where). `benchmarks/demo_samples.jsonl` is a 16-sample demo, not a benchmark.

## Tests
- Backend (40 tests, no key or internet needed): `cd backend && python -m unittest discover -s tests`
- Dashboard (opens it in a fake browser): `cd dashboard/tests && npm install jsdom && node smoke.js`

## Layout
`backend/` FastAPI app (`app/stages/` = one file per pipeline stage, `app/schemas.py` = the contract), `ml/` dataset and training,
`benchmarks/` ablation, `tests/`. `dashboard/index.html` the UI. `docs/` demo script and report text.

## Safety notes
- Code around each finding (and Builder prompts) is sent to the LLM provider you configure. Do not scan code you may not share.
- Generated code is parsed and scanned, never executed by the backend. The Builder preview runs in a sandboxed iframe.
- CORS is open for local use. Restrict `allow_origins` in `backend/app/main.py` before putting this on a public server.
- Never commit `backend/.env`. It is in `.gitignore`.
