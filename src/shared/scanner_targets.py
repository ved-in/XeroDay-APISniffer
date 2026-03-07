import json
import re
from typing import Callable, List, Optional

import requests


GITHUB_REPO_URL_PATTERN = re.compile(
    r"(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:\.git)?(?:[/?#][^\s]*)?",
    re.IGNORECASE,
)
GITHUB_REPO_NAME_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.\-/])([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:\.git)?(?![A-Za-z0-9_.\-/])"
)
GITHUB_REPO_FULL_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
REPO_CONTEXT_TERMS = ("github", "repo", "repository", "repositories")
REPO_BATCH_IGNORED_TOKENS = {"and"}
AI_REPO_TARGET_PROMPT = '''You extract GitHub repository targets for an automated security scanner.
Return valid JSON only in this exact format:
{
  "understanding": "short summary",
  "targets": ["owner/repo", "owner/another-repo"]
}

Rules:
1. Capture every GitHub repository target present in the user's text.
2. Support pasted GitHub URLs, multiple URLs in one message, bare owner/repo names, and repo subpaths by reducing them to owner/repo.
3. Deduplicate exact duplicates.
4. Ignore non-GitHub links and text that does not point to a repository.
5. Do not invent repositories that are not present in the input.
6. If there are no valid repositories, return an empty targets array.
'''

# This is used to salvage the JSON payload when the model wraps it in extra text.
def extract_json_blob(raw_text: str) -> dict:
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        start = raw_text.find("{")
        end = raw_text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(raw_text[start:end + 1])
        raise


def repo_identity(repo_name: str) -> str:
    return (repo_name or "").strip().lower()


def normalize_repo_name(repo_name: str) -> str:
    normalized_name = repo_name.strip().rstrip("/")
    if normalized_name.endswith(".git"):
        normalized_name = normalized_name[:-4]
    return normalized_name


def prompt_contains_term(prompt_text: str, term: str) -> bool:
    lowered_prompt = prompt_text.lower()
    if term.isalpha():
        return re.search(rf"\b{re.escape(term)}\b", lowered_prompt) is not None
    return term in lowered_prompt


def is_valid_repo_name(repo_name: str) -> bool:
    normalized_name = normalize_repo_name(repo_name)
    return GITHUB_REPO_FULL_PATTERN.fullmatch(normalized_name) is not None


def prompt_has_repo_context(prompt_text: str) -> bool:
    return any(prompt_contains_term(prompt_text, term) for term in REPO_CONTEXT_TERMS)


def is_repo_batch_prompt(prompt_text: str) -> bool:
    prompt_without_urls = GITHUB_REPO_URL_PATTERN.sub(" ", prompt_text)
    raw_tokens = [token for token in re.split(r"[\s,;]+", prompt_without_urls) if token]
    if not raw_tokens:
        return False

    saw_repo_target = False
    for raw_token in raw_tokens:
        cleaned_token = raw_token.strip("`'\"()[]{}")
        if not cleaned_token or cleaned_token.lower() in REPO_BATCH_IGNORED_TOKENS:
            continue
        if not is_valid_repo_name(cleaned_token):
            return False
        saw_repo_target = True

    return saw_repo_target


def build_repo_data(repo_name: str) -> Optional[dict]:
    normalized_name = normalize_repo_name(repo_name)
    if not GITHUB_REPO_FULL_PATTERN.fullmatch(normalized_name):
        return None
    return {"name": normalized_name, "url": f"https://github.com/{normalized_name}"}

# This is used to reduce pasted GitHub text to a clean owner/repo target.
def normalize_repo_target(url_text: str) -> Optional[dict]:
    candidate = url_text.strip()
    if not candidate:
        return None

    match = GITHUB_REPO_URL_PATTERN.search(candidate)
    if not match:
        bare_candidate = normalize_repo_name(candidate)
        if not is_valid_repo_name(bare_candidate):
            return None
        match = GITHUB_REPO_FULL_PATTERN.fullmatch(bare_candidate)
    if not match:
        return None

    repo_name = match.group(1) if match.lastindex else match.group(0)
    return build_repo_data(repo_name)


def dedupe_repo_targets(repo_targets: List[dict]) -> List[dict]:
    unique_targets = {}
    for repo_data in repo_targets:
        repo_key = repo_identity(repo_data.get("name", ""))
        if repo_key:
            unique_targets[repo_key] = repo_data
    return list(unique_targets.values())


def extract_repo_targets_regex(prompt_text: str) -> List[dict]:
    extracted_targets = []
    allow_bare_targets = prompt_has_repo_context(prompt_text) or is_repo_batch_prompt(prompt_text)

    for match in GITHUB_REPO_URL_PATTERN.finditer(prompt_text):
        repo_data = build_repo_data(match.group(1))
        if repo_data is not None:
            extracted_targets.append(repo_data)

    if allow_bare_targets:
        for match in GITHUB_REPO_NAME_PATTERN.finditer(prompt_text):
            repo_name = match.group(1)
            if not is_valid_repo_name(repo_name):
                continue
            repo_data = build_repo_data(repo_name)
            if repo_data is not None:
                extracted_targets.append(repo_data)

    return dedupe_repo_targets(extracted_targets)

# This is used to let the model act as a loose parser while keeping the final output strict.
# For example, if the model returns a repo subpath, it is normalized back to owner/repo.
def extract_repo_targets_with_ai(
    prompt_text: str,
    groq_api_key: str,
    api_url: str,
    model: str,
    timeout: int,
    log_message: Callable[[str], None],
) -> List[dict]:
    if not groq_api_key:
        log_message("[bold yellow][!] GROQ_API_KEY not set. Using direct GitHub target extraction only.[/]")
        return []

    headers = {
        "Authorization": f"Bearer {groq_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": AI_REPO_TARGET_PROMPT},
            {"role": "user", "content": prompt_text},
        ],
        "temperature": 0,
    }

    try:
        response = requests.post(api_url, headers=headers, json=payload, timeout=timeout)
        response.raise_for_status()
        response_data = response.json()
        ai_payload = extract_json_blob(response_data["choices"][0]["message"]["content"])
    except Exception as exc:
        log_message(f"[bold red][!] AI target extraction failed:[/] {exc}")
        return []

    raw_targets = ai_payload.get("targets", [])
    if not isinstance(raw_targets, list):
        return []

    normalized_targets = []
    for raw_target in raw_targets:
        if isinstance(raw_target, dict):
            candidate = raw_target.get("name") or raw_target.get("repo") or raw_target.get("url") or ""
        else:
            candidate = str(raw_target)
        repo_data = normalize_repo_target(candidate)
        if repo_data is not None:
            normalized_targets.append(repo_data)

    return dedupe_repo_targets(normalized_targets)

# This merges the AI result with the regex result so obvious targets still work without the model.
def resolve_repo_targets(
    prompt_text: str,
    groq_api_key: str,
    api_url: str,
    model: str,
    timeout: int,
    log_message: Callable[[str], None],
) -> List[dict]:
    ai_targets = extract_repo_targets_with_ai(prompt_text, groq_api_key, api_url, model, timeout, log_message)
    regex_targets = extract_repo_targets_regex(prompt_text)
    return dedupe_repo_targets([*ai_targets, *regex_targets])
