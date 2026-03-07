import re
from functools import lru_cache
from typing import Dict, Iterable, List, Set

from .api_signatures import API_SIGNATURE_CATEGORIES


NOISE_TOKENS = {
    "access",
    "anon",
    "api",
    "bot",
    "classic",
    "custom",
    "fine",
    "grained",
    "id",
    "jwt",
    "key",
    "keys",
    "legacy",
    "oauth",
    "project",
    "role",
    "secret",
    "secrets",
    "server",
    "service",
    "token",
    "tokens",
    "upload",
    "url",
    "user",
    "webhook",
    "webhooks",
}

TOPIC_TERMS = {
    "ai": ("ai", "llm", "model", "models", "openai", "anthropic", "groq", "xai", "grok", "openrouter", "huggingface", "replicate", "cerebras", "google", "gcp"),
    "cloud": ("cloud", "aws", "gcp", "google", "digitalocean", "heroku", "databricks"),
    "database": ("database", "databases", "db", "backend", "backends", "supabase", "firebase", "planetscale", "airtable", "appwrite", "deta", "pocketbase", "databricks"),
    "source_control": ("git", "github", "gitlab", "source control", "source-control"),
    "package": ("package", "packages", "registry", "registries", "npm", "pypi"),
    "communication": ("communication", "chat", "messaging", "discord", "slack", "telegram", "webhook", "webhooks"),
    "payment": ("payment", "payments", "billing", "commerce", "stripe", "square", "shopify"),
    "email": ("email", "mail", "smtp", "sendgrid", "mailgun", "twilio", "sms"),
}

TOPIC_LABELS = {
    "ai": "AI-related categories",
    "cloud": "cloud-related categories",
    "database": "database-related categories",
    "source_control": "source-control categories",
    "package": "package-registry categories",
    "communication": "communication categories",
    "payment": "payment-related categories",
    "email": "email/messaging categories",
}

ALL_CATEGORY_QUERY_TERMS = (
    "all categories",
    "all api keys",
    "all the api keys",
    "all api types",
    "all api key types",
    "all signatures",
    "available categories",
    "show all api keys",
    "show all the api keys",
    "what categories are there",
    "which categories are there",
    "list categories",
)

SUMMARY_QUERY_TERMS = (
    "how many",
    "count",
    "number of",
    "available categories",
    "what categories",
    "which categories",
    "what types",
    "which types",
)

NON_ALNUM_PATTERN = re.compile(r"[^a-z0-9]+")
CATEGORY_ORDER = {category: idx for idx, category in enumerate(API_SIGNATURE_CATEGORIES)}


def tokenize_text(text: str) -> Set[str]:
    normalized = NON_ALNUM_PATTERN.sub(" ", text.lower())
    return {token for token in normalized.split() if token and token not in NOISE_TOKENS}


def query_contains_term(query_text: str, term: str) -> bool:
    lowered_query = query_text.lower()
    if " " in term or "-" in term:
        return term.lower() in lowered_query
    return re.search(rf"\b{re.escape(term.lower())}\b", lowered_query) is not None


def normalize_categories(categories: Iterable[str]) -> List[str]:
    unique_categories = {category for category in categories if category in CATEGORY_ORDER}
    return sorted(unique_categories, key=CATEGORY_ORDER.get)


@lru_cache(maxsize=1)
def _topic_token_map() -> Dict[str, Set[str]]:
    return {
        topic: {token for term in terms for token in tokenize_text(term)}
        for topic, terms in TOPIC_TERMS.items()
    }


@lru_cache(maxsize=1)
def _category_token_map() -> Dict[str, Set[str]]:
    return {category: tokenize_text(category) for category in API_SIGNATURE_CATEGORIES}


@lru_cache(maxsize=1)
def _category_topic_map() -> Dict[str, Set[str]]:
    topic_tokens = _topic_token_map()
    category_topics: Dict[str, Set[str]] = {}

    for category, category_tokens in _category_token_map().items():
        category_topics[category] = {
            topic
            for topic, tokens in topic_tokens.items()
            if category_tokens & tokens
        }

    return category_topics


def detect_query_topics(user_query: str) -> List[str]:
    matched_topics = []
    lowered_query = user_query.lower()

    for topic, terms in TOPIC_TERMS.items():
        if any(query_contains_term(lowered_query, term) for term in terms):
            matched_topics.append(topic)

    return matched_topics


def infer_categories_from_query(user_query: str) -> List[str]:
    lowered_query = user_query.lower()
    if any(query_contains_term(lowered_query, term) for term in ALL_CATEGORY_QUERY_TERMS):
        return list(API_SIGNATURE_CATEGORIES)

    query_tokens = tokenize_text(user_query)
    inferred = []

    for category, category_tokens in _category_token_map().items():
        if category.lower() in lowered_query or (query_tokens and query_tokens & category_tokens):
            inferred.append(category)

    matched_topics = set(detect_query_topics(user_query))
    if matched_topics:
        for category, category_topics in _category_topic_map().items():
            if category_topics & matched_topics:
                inferred.append(category)

    return normalize_categories(inferred)


def is_summary_query(user_query: str) -> bool:
    lowered_query = user_query.lower()
    return any(query_contains_term(lowered_query, term) for term in SUMMARY_QUERY_TERMS)


def describe_scope(user_query: str, target_categories: List[str]) -> str:
    if not target_categories:
        return "the selected categories"
    if len(target_categories) == len(API_SIGNATURE_CATEGORIES):
        return "all tracked signature categories"

    matched_topics = detect_query_topics(user_query)
    for topic in matched_topics:
        label = TOPIC_LABELS.get(topic)
        if label:
            return label

    if len(target_categories) == 1:
        return target_categories[0]
    return "the selected categories"
