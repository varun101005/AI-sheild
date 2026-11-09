"""Turns a ScanRequest (paste / files / github) into a list of source files."""
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import NamedTuple

from .schemas import ScanRequest

EXTS = (".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".h", ".cpp", ".cc", ".hpp", ".html", ".htm")
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "target"}
MAX_FILES = 200
MAX_BYTES = 300_000
REPO_RE = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+?(?:\.git)?/?$")
BRANCH_RE = re.compile(r"^[\w./-]{1,100}$")


class SourceFile(NamedTuple):
    path: str
    text: str


class InputError(ValueError):
    """Bad input from the user. Becomes an HTTP 400."""


def collect(req: ScanRequest) -> tuple[list[SourceFile], list[str]]:
    if req.source == "paste":
        if not req.code or not req.code.strip():
            raise InputError("No code provided.")
        # FIX 4a: enforce size limit on paste mode too
        if len(req.code.encode("utf-8", errors="replace")) > MAX_BYTES:
            raise InputError(f"Pasted code exceeds the {MAX_BYTES // 1000} KB limit.")
        name = req.filename or "snippet.py"
        warn = [] if name.lower().endswith(EXTS) else [
            "This file extension is not a supported language (Python, JavaScript, TypeScript, Java, C, C++, HTML), so no scanner "
            "ran. Zero findings does NOT mean the code is safe."]
        return [SourceFile(name, req.code)], warn
    if req.source == "files":
        files = [SourceFile(f.name, f.content) for f in req.files if f.name.endswith(EXTS)]
        if not files:
            raise InputError("No supported files in the upload (Python, JavaScript, TypeScript, Java, C, C++ or HTML).")
        return _cap(files)
    return _clone(req.repo_url or "", req.branch.strip())


def _cap(files: list[SourceFile]) -> tuple[list[SourceFile], list[str]]:
    if len(files) > MAX_FILES:
        return files[:MAX_FILES], [f"Only the first {MAX_FILES} of {len(files)} files were scanned."]
    return files, []


def _clone(url: str, branch: str) -> tuple[list[SourceFile], list[str]]:
    """Clone a public GitHub repo (shallow), collect supported source files.

    FIX 4b: Use TemporaryDirectory context manager to guarantee cleanup.
    FIX 5:  Kill the git subprocess explicitly on timeout so it doesn't
            linger as an orphan process consuming resources.
    FIX 3:  Added pre-flight check for 'git' on PATH with a helpful error.
    """
    if not _git_available():
        raise InputError(
            "git is not found on PATH. Install Git (https://git-scm.com) and make sure "
            "it is accessible from the command line, then restart the server."
        )
    if not REPO_RE.match(url):
        raise InputError("Repo URL must look like https://github.com/owner/name")
    if branch and (not BRANCH_RE.match(branch) or branch.startswith("-") or ".." in branch):
        raise InputError("Invalid branch name.")

    cmd = ["git", "clone", "--depth", "1"] + (["--branch", branch] if branch else []) + ["--", url]

    # TemporaryDirectory cleans up automatically even if the process is killed.
    with tempfile.TemporaryDirectory(prefix="csai_") as tmp_str:
        dest = Path(tmp_str) / "repo"
        cmd = cmd + [str(dest)]
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        try:
            _, stderr_bytes = proc.communicate(timeout=90)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()          # drain pipes so the process exits cleanly
            raise InputError("Cloning timed out.")

        if proc.returncode != 0:
            raise InputError("Could not clone the repo. Check the URL and branch, and that the repo is public.")

        files = []
        for p in sorted(dest.rglob("*")):
            rel = p.relative_to(dest)
            if (p.is_file() and p.suffix in EXTS and not SKIP_DIRS & set(rel.parts)
                    and p.stat().st_size <= MAX_BYTES):
                files.append(SourceFile(rel.as_posix(), p.read_text(errors="ignore")))
        return _cap(files)


def _git_available() -> bool:
    """Return True if git is on PATH."""
    try:
        subprocess.run(["git", "--version"], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False
