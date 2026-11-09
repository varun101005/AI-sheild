# conftest.py — makes pytest discover tests/ correctly and provides shared fixtures.
# FIX (compatibility): without this file pytest cannot find the app package when run
# from the backend/ directory, because sys.path does not include the project root.
import sys
from pathlib import Path

# Ensure the backend/ directory is on sys.path so "from app.xxx import yyy" works in tests.
sys.path.insert(0, str(Path(__file__).resolve().parent))
