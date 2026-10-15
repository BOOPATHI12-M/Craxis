import sys
from pathlib import Path

ML_DIR = Path(__file__).resolve().parent.parent
ROOT = ML_DIR.parent
for p in (str(ML_DIR), str(ROOT / "tools")):
    if p not in sys.path:
        sys.path.insert(0, p)
