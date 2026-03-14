import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, Optional


ROOT = Path(__file__).resolve().parents[2]
DEF_PATH = ROOT / "config" / "ai_policy.json"
ENV_KEY = "AI_POLICY_PATH"


def _log(log_fn: Optional[Callable[[str], None]], msg: str) -> None:
    if log_fn:
        log_fn(msg)


# We cache the policy so repeated prompts (>10) don't re-read disk every time.
# So the spam Enter 20x and we still keep one in-memory copy.
@lru_cache(maxsize=1)
def _load_pol(path: Optional[str] = None) -> Dict[str, Any]:
    pth = Path(path or os.environ.get(ENV_KEY, "") or DEF_PATH)
    try:
        with pth.open("r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}


def load_pol(path: Optional[str] = None, log_fn: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    pol = _load_pol(path)
    if not pol:
        pth = Path(path or os.environ.get(ENV_KEY, "") or DEF_PATH)
        _log(log_fn, f"[bold red][X] AI policy missing or invalid: {pth}[/]")
    return pol


def fill_tpl(tpl: str, rep: Dict[str, str]) -> str:
    # We do a simple token swap, so prompts can include JSON examples without escaping braces.
    # So, "__CATEGORIES__" -> ["AWS Access Key ID", "OpenAI API Key (Legacy)"].
    out = tpl
    for key, val in rep.items():
        out = out.replace(key, val)
    return out
