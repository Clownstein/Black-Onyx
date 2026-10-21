import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
for mod in list(sys.modules):
    if mod == "app" or mod.startswith("app."):
        del sys.modules[mod]
