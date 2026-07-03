"""Make `import deponent` work when running the test suite from the repo root
without an editable install (CI-friendly)."""
import sys
from pathlib import Path

ROOT = str(Path(__file__).resolve().parent)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
