import json
from pathlib import Path
from typing import Dict, List, Optional, Pattern

import re


ROOT = Path(__file__).resolve().parents[2]
DEF_PATH = ROOT / "data" / "signatures.json"


def _load(pth: Optional[str] = None) -> List[dict]:
    src = Path(pth or DEF_PATH)
    with src.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return list(data.get("signatures", []))


def sig_names(pth: Optional[str] = None) -> List[str]:
    return [str(item.get("name", "")).strip() for item in _load(pth) if str(item.get("name", "")).strip()]


def build_sigs(include_heroku: bool = True, pth: Optional[str] = None) -> Dict[str, Pattern[str]]:
    # The JSON keeps raw patterns, so adding a new rule is just one JSON entry.
    # Example: {"name":"Stripe Secret Key","pattern":"\\bsk_live_...\\b"}.
    out: Dict[str, Pattern[str]] = {}
    for item in _load(pth):
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        tags = item.get("tags") or []
        if not include_heroku and "heroku" in tags:
            continue
        pat = str(item.get("pattern", ""))
        if not pat:
            continue
        out[name] = re.compile(pat)
    return out
