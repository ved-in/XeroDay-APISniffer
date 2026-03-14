from typing import Dict, List, Pattern

from .signature_loader import build_sigs, sig_names


HEROKU_API_SIGNATURE_NAME = "Heroku API Key"

# The base list is now data-driven. Edit data/signatures.json to add or update rules.
# Example: add a new "Stripe Secret Key" regex there and it shows up here.
BASE_API_SIGNATURES: Dict[str, Pattern[str]] = build_sigs(include_heroku=True)
API_SIGNATURE_CATEGORIES: List[str] = sig_names()


def build_api_signatures(include_heroku: bool = True) -> Dict[str, Pattern[str]]:
    return build_sigs(include_heroku=include_heroku)