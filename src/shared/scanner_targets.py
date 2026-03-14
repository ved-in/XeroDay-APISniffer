import re
from typing import Callable, List, Optional

from .ai_client import ask_json
from .ai_policy import load_pol


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
    pol: Optional[dict],
    log_message: Callable[[str], None],
) -> List[dict]:
    if not groq_api_key:
        log_message("[bold yellow][!] GROQ_API_KEY not set. Using direct GitHub target extraction only.[/]")
        return []

    pol = pol or load_pol(log_fn=log_message)
    if not pol:
        return []

    sys_txt = str(pol.get("repo_targets", {}).get("system", "")).strip()
    if not sys_txt:
        log_message("[bold red][!] AI repo-target policy missing.[/]")
        return []

    try:
        msgs = [
            {"role": "system", "content": sys_txt},
            {"role": "user", "content": prompt_text},
        ]
        ai_payload = ask_json(msgs, groq_api_key, pol.get("llm", {}))
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
    pol: Optional[dict],
    log_message: Callable[[str], None],
) -> List[dict]:
    ai_targets = extract_repo_targets_with_ai(prompt_text, groq_api_key, pol, log_message)
    regex_targets = extract_repo_targets_regex(prompt_text)
    return dedupe_repo_targets([*ai_targets, *regex_targets])
