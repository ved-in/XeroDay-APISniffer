import re
from typing import Dict, List, Pattern


HEROKU_API_SIGNATURE_NAME = "Heroku API Key"

BASE_API_SIGNATURES: Dict[str, Pattern[str]] = {
    "OpenAI API Key (Legacy)": re.compile(r"\bsk-[a-zA-Z0-9]{48}\b"),
    "OpenAI API Key (Project)": re.compile(r"\bsk-proj-[a-zA-Z0-9\-_]{48,}\b"),
    "Anthropic API Key": re.compile(r"\bsk-ant-api03-[a-zA-Z0-9\-_]{60,100}\b"),
    "Google API/GCP Key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "OpenRouter API Key": re.compile(r"\bsk-or-v1-[a-zA-Z0-9]{64}\b"),
    "xAI (Grok) API Key": re.compile(r"\bxai-[a-zA-Z0-9\-_]{60,100}\b"),
    "Groq API Key": re.compile(r"\bgsk_[a-zA-Z0-9]{32,64}\b"),
    "HuggingFace Token": re.compile(r"\bhf_[a-zA-Z]{34}\b"),
    "Replicate Token": re.compile(r"\br8_[a-zA-Z0-9]{37}\b"),
    "Cerebras Token": re.compile(r"\bcs-[a-zA-Z0-9]{32,64}\b"),
    "AWS Access Key ID": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "AWS Session Token": re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    "DigitalOcean PAT": re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),
    HEROKU_API_SIGNATURE_NAME: re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    "Mapbox API Key": re.compile(r"\b(?:pk|sk)\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "Sentry Token": re.compile(r"\bsntrys_[a-zA-Z0-9_-]{64,}\b"),
    "Databricks PAT": re.compile(r"\bdapi[a-h0-9]{32}\b"),
    "GitHub Classic PAT": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b"),
    "GitHub Fine-Grained PAT": re.compile(r"\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b"),
    "GitLab PAT": re.compile(r"\bglpat-[a-zA-Z0-9\-]{20}\b"),
    "NPM Access Token": re.compile(r"\b(?:npm_[a-zA-Z0-9]{36})\b"),
    "PyPI Upload Token": re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,150}\b"),
    "Postman API Key": re.compile(r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b"),
    "Discord Bot Token": re.compile(r"\b[MNO][a-zA-Z0-9_-]{23,27}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,38}\b"),
    "Discord Webhook": re.compile(r"https://discord\.com/api/webhooks/[0-9]{17,19}/[a-zA-Z0-9_-]{60,68}"),
    "Slack Bot Token": re.compile(r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b"),
    "Slack User Token": re.compile(r"\bxox[pausr]-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b"),
    "Slack Webhook": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,10}/B[a-zA-Z0-9_]{8,10}/[a-zA-Z0-9_]{24}"),
    "Telegram Bot Token": re.compile(r"\b[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b"),
    "Twilio API Key": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    "SendGrid API Key": re.compile(r"\bSG\.[a-zA-Z0-9_\-\.]{66}\b"),
    "Mailgun API Key": re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"),
    "Stripe Secret Key": re.compile(r"\b(?:sk|rk)_(?:test|live)_[0-9a-zA-Z]{24,99}\b"),
    "Square Access Token": re.compile(r"\bsq0atp-[0-9A-Za-z\-_]{22,43}\b"),
    "Square OAuth Secret": re.compile(r"\bsq0csp-[0-9A-Za-z\-_]{43}\b"),
    "Shopify Access Token": re.compile(r"\bshpat_[a-fA-F0-9]{32}\b"),
    "Shopify Custom App": re.compile(r"\bshpca_[a-fA-F0-9]{32}\b"),
    "Supabase PAT": re.compile(r"\bsbp_[a-zA-Z0-9]{40}\b"),
    "Supabase Anon/Service Role JWT": re.compile(r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
    "Firebase Server Key": re.compile(r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b"),
    "Firebase Database URL": re.compile(r"https:\/\/[a-z0-9-]+\.firebaseio\.com"),
    "PlanetScale Password": re.compile(r"\bpscale_pw_[a-zA-Z0-9_\.\-]{43}\b"),
    "PlanetScale OAuth Token": re.compile(r"\bpscale_oauth_[a-zA-Z0-9_\.\-]{32,64}\b"),
    "Airtable PAT": re.compile(r"\bpat[a-zA-Z0-9]{14}\.[a-zA-Z0-9]{64}\b"),
    "Appwrite API Key": re.compile(r"(?i)appwrite[\w\s=-]{0,20}(?:key|token|secret)[\w\s=:\"\'-]{0,10}\b([a-zA-Z0-9\-_]{32,})\b"),
    "Deta Token": re.compile(r"(?i)deta[\w\s=-]{0,20}(?:key|token)[\w\s=:\"\'-]{0,10}\b([a-zA-Z0-9_]{32,})\b"),
    "PocketBase Token": re.compile(r"(?i)pocketbase[\w\s=-]{0,20}(?:key|token|admin)[\w\s=:\"\'-]{0,10}\b([a-zA-Z0-9\-_]{32,})\b"),
}

API_SIGNATURE_CATEGORIES: List[str] = list(BASE_API_SIGNATURES.keys())


def build_api_signatures(include_heroku: bool = True) -> Dict[str, Pattern[str]]:
    signatures = dict(BASE_API_SIGNATURES)
    if not include_heroku:
        signatures.pop(HEROKU_API_SIGNATURE_NAME, None)
    return signatures