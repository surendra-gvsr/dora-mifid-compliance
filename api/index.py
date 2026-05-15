import sys
import os

# Ensure the project root is on the path so Vercel can find our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from main import app  # noqa: F401 — Vercel picks up `app`
