"""The contract. Every stage reads and writes these shapes, and the dashboard expects them."""
from typing import Literal, Optional
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# FIX 1: Python 3.9-compatible Optional syntax (replaces str | None unions).
# FIX 2: Added max_length guards on every user-supplied string to prevent
#         memory exhaustion from oversized payloads.
# ---------------------------------------------------------------------------

MAX_CODE_BYTES = 300_000   # ~300 KB per file / paste
MAX_FILENAME   = 512


class FileIn(BaseModel):
    name: str = Field(max_length=MAX_FILENAME)
    content: str = Field(max_length=MAX_CODE_BYTES)


class ScanRequest(BaseModel):
    source: Literal["paste", "github", "files"]
    filename: str = Field(default="snippet.py", max_length=MAX_FILENAME)   # paste
    code: Optional[str] = Field(default=None, max_length=MAX_CODE_BYTES)   # paste
    repo_url: Optional[str] = Field(default=None, max_length=512)          # github
    branch: str = Field(default="", max_length=100)                        # github
    files: list[FileIn] = Field(default_factory=list)                      # files


class Static(BaseModel):
    hit: bool = False
    note: str = ""


class LLM(BaseModel):
    verdict: str = "unsure"               # exploitable | not exploitable | unsure
    score: float = 0.0


class Clf(BaseModel):
    score: Optional[float] = None         # None = no trained model, so no signal


class Signals(BaseModel):
    static: Static = Field(default_factory=Static)
    llm: LLM = Field(default_factory=LLM)
    clf: Clf = Field(default_factory=Clf)


class Consistency(BaseModel):
    runs: int = 0
    same: int = 0


class Fix(BaseModel):
    patch: list[str] = Field(default_factory=list)   # lines starting with "- " or "+ "
    verified: bool = False
    attempts: int = 0


class Finding(BaseModel):
    id: str
    file: str
    line: int
    cwe: str
    type: str
    severity: Literal["high", "medium", "low"]
    confidence: float = 0.0
    signals: Signals = Field(default_factory=Signals)
    consistency: Consistency = Field(default_factory=Consistency)
    explanation: str = ""
    code: list[str] = Field(default_factory=list)
    fix: Fix = Field(default_factory=Fix)
    reason: str = ""                      # filled only when the finding is dismissed
    llm_checked: bool = Field(default=False, exclude=True)   # internal flag, never sent to the dashboard


class ScanResponse(BaseModel):
    findings: list[Finding]
    dismissed: list[Finding]
    notes: list[str] = Field(default_factory=list)
