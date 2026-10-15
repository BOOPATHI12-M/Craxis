"""Generate shared/config.js from shared/config.json (single source of truth).

Usage:
    python tools/sync_config.py          # write shared/config.js
    python tools/sync_config.py --check  # exit 1 if config.js is stale
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "shared" / "config.json"
DST = ROOT / "shared" / "config.js"

HEADER = "// AUTO-GENERATED from shared/config.json by tools/sync_config.py. Do not edit.\n"


def render() -> str:
    cfg = json.loads(SRC.read_text(encoding="utf-8"))
    body = json.dumps(cfg, indent=2, ensure_ascii=False)
    return (
        HEADER
        + "(function (root) {\n"
        + f"  var config = {body};\n"
        + "  if (typeof module === 'object' && module.exports) { module.exports = config; }\n"
        + "  else { root.AIPHISH_CONFIG = config; }\n"
        + "})(typeof self !== 'undefined' ? self : this);\n"
    )


def main() -> int:
    text = render()
    if "--check" in sys.argv:
        if not DST.exists() or DST.read_text(encoding="utf-8") != text:
            print("shared/config.js is stale. Run: python tools/sync_config.py")
            return 1
        print("shared/config.js is up to date.")
        return 0
    DST.write_text(text, encoding="utf-8", newline="\n")
    print(f"Wrote {DST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
