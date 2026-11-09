import os
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from .builder import BuildError, BuildRequest, BuildResponse, build
from .inputs import InputError, collect
from .pipeline import run_pipeline
from .schemas import ScanRequest, ScanResponse

# ---------------------------------------------------------------------------
# FIX 2: CORS – default to localhost only; override via ALLOW_ORIGINS env var.
#   Production example: ALLOW_ORIGINS=https://app.example.com
#   Multiple origins: ALLOW_ORIGINS=https://a.example.com,https://b.example.com
# ---------------------------------------------------------------------------
_raw_origins = os.getenv("ALLOW_ORIGINS", "http://localhost:8000").strip()
ALLOW_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app = FastAPI(title="CodeShieldAI")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOW_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# FIX 8: Optional API-key authentication.
#   Set SHIELD_API_KEY in .env to enable. If not set, auth is disabled
#   (safe for local use; always set it before exposing the server publicly).
# ---------------------------------------------------------------------------
_API_KEY = os.getenv("SHIELD_API_KEY", "")


def _auth(x_api_key: str = Header(default="")) -> None:
    """Dependency: reject requests that do not carry the configured API key."""
    if _API_KEY and x_api_key != _API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-Api-Key header.")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse, dependencies=[Depends(_auth)])
def scan(req: ScanRequest):
    try:
        files, notes = collect(req)
    except InputError as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return run_pipeline(files, notes)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/build", response_model=BuildResponse, dependencies=[Depends(_auth)])
def build_endpoint(req: BuildRequest):
    try:
        return build(req)
    except BuildError as e:
        raise HTTPException(status_code=e.status, detail=str(e))


UI = Path(__file__).resolve().parent.parent.parent / "dashboard"
if UI.is_dir():                      # serves the dashboard at /ui/ so one command runs everything
    app.mount("/ui", StaticFiles(directory=UI, html=True), name="ui")

    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse("/ui/")
