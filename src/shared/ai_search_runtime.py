import json
import os
from typing import Dict, List, Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from .api_signatures import API_SIGNATURE_CATEGORIES
from .category_routing import (
    describe_scope,
    infer_categories_from_query,
    is_summary_query,
    normalize_categories,
)


LEAKS_JSON = "leaked_keys.json"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"
AVAILABLE_CATEGORIES = list(API_SIGNATURE_CATEGORIES)


def count_unique_repositories(entries: list) -> int:
    return len(
        {
            str(entry.get("repo", "")).strip().lower()
            for entry in entries
            if isinstance(entry, dict) and entry.get("repo")
        }
    )


def count_total_findings(entries: list) -> int:
    total = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        findings = entry.get("findings", [])
        total += len(findings) if isinstance(findings, list) else int(entry.get("total_secrets", 0) or 0)
    return total


def render_header(console: Console) -> None:
    console.print(
        Panel.fit(
            "[bold magenta]API Sniffer - AI Database Query Engine[/]\n[dim]Powered by Llama-3 via Groq[/]",
            border_style="magenta",
        )
    )


def get_groq_api_key(console: Console) -> str:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        console.print("[bold yellow][!] GROQ_API_KEY environment variable not found.[/]")
        api_key = Prompt.ask("[bold cyan]Please enter your Groq API Key (gsk_...)[/]", password=True, console=console)
        os.environ["GROQ_API_KEY"] = api_key
    return api_key


def load_database(console: Console) -> list:
    if not os.path.exists(LEAKS_JSON):
        console.print(f"[bold red][X] Database file '{LEAKS_JSON}' not found. Please run the scanner first.[/]")
        return []

    try:
        with open(LEAKS_JSON, "r", encoding="utf-8") as file_ptr:
            raw_data = json.load(file_ptr)
            if not isinstance(raw_data, list):
                raise ValueError("Database file does not contain a JSON list.")
            return raw_data
    except Exception as error:
        console.print(f"[bold red][X] Error reading database: {error}[/]")
        return []


def render_database_overview(console: Console, db_data: list) -> None:
    repo_count = count_unique_repositories(db_data)
    total_findings = count_total_findings(db_data)
    console.print(f"[green]Loaded database with {repo_count} repositories and {total_findings} findings.[/]")


def extract_json_blob(raw_text: str) -> Dict[str, object]:
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        start = raw_text.find("{")
        end = raw_text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(raw_text[start : end + 1])
        raise


def collect_matches(target_categories: List[str], db_data: list) -> List[Dict[str, str]]:
    category_set = set(target_categories)
    collected = []

    for repo_entry in db_data:
        repo_name = repo_entry.get("repo", "Unknown")
        findings = repo_entry.get("findings", [])

        for finding in findings:
            if finding.get("type") in category_set:
                collected.append(
                    {
                        "repo": repo_name,
                        "type": finding.get("type", "Unknown"),
                        "secret": finding.get("secret", "N/A"),
                        "file": finding.get("file", "Unknown"),
                    }
                )

    return collected


def ask_ai_for_pointers(user_query: str, api_key: str, console: Console) -> dict:
    system_prompt = f"""You are X3r0Day's API Sniffer's AI Database Router.
Your ONLY job is to translate a user's natural language request into exact database category pointers.
You must return a valid JSON object.

AVAILABLE EXACT CATEGORIES:
{json.dumps(AVAILABLE_CATEGORIES)}

INSTRUCTIONS:
1. Analyze what the user is asking for (for example "AWS", "discord", "all AI keys", "all databases").
2. Match their intent to the AVAILABLE EXACT CATEGORIES.
3. If they ask for something broad like "AI keys" or "database categories", include every relevant category from the list.
4. If they ask a count/list/availability question, still return the relevant categories and set "intent" to "summary".
5. DO NOT make up categories. If they ask for something not in the list, leave the array empty.
6. You MUST return your answer in the following JSON format ONLY:
{{
    "understanding": "Short 1-sentence confirmation of what you are querying.",
    "intent": "search",
    "target_categories": ["Exact Category 1", "Exact Category 2"]
}}

Valid intent values:
- "search" for normal result lookup
- "summary" for count/list/category summary requests
"""

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": GROQ_MODEL,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_query},
        ],
        "temperature": 0,
    }

    try:
        response = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        return extract_json_blob(data["choices"][0]["message"]["content"])
    except Exception as error:
        console.print(f"[bold red][X] Groq API Error: {error}[/]")
        return {}


def normalize_ai_route(ai_instructions: dict) -> Dict[str, object]:
    understanding = str(ai_instructions.get("understanding", "")).strip() if isinstance(ai_instructions, dict) else ""
    intent = str(ai_instructions.get("intent", "search")).strip().lower() if isinstance(ai_instructions, dict) else "search"
    if intent not in {"search", "summary"}:
        intent = "search"

    raw_categories = ai_instructions.get("target_categories", []) if isinstance(ai_instructions, dict) else []
    if not isinstance(raw_categories, list):
        raw_categories = []

    return {
        "understanding": understanding,
        "intent": intent,
        "target_categories": normalize_categories([str(category) for category in raw_categories]),
    }


def search_and_display(target_categories: List[str], db_data: list, console: Console) -> None:
    if not target_categories:
        console.print("[bold yellow]The AI could not map your query to any known API key signatures in our system.[/]")
        return

    console.print(f"\n[dim]=> Local Script is now scanning database for: {', '.join(target_categories)}[/]")

    matches = collect_matches(target_categories, db_data)
    table = Table(title="[bold cyan]API Sniffer's Database Search Results[/]", border_style="cyan", expand=True)
    table.add_column("Repository", style="magenta", overflow="fold", ratio=2)
    table.add_column("API Type", style="yellow", overflow="fold", ratio=2)
    table.add_column("Secret / Key", style="red", overflow="fold", ratio=4)
    table.add_column("File / Origin", style="dim", overflow="fold", ratio=2)

    for match in matches:
        table.add_row(match["repo"], match["type"], match["secret"], match["file"])

    if matches:
        repo_count = len({match["repo"] for match in matches})
        finding_label = "finding" if len(matches) == 1 else "findings"
        repo_label = "repository" if repo_count == 1 else "repositories"
        console.print(table)
        console.print(
            f"[bold green]Successfully pulled {len(matches)} matching {finding_label} "
            f"across {repo_count} {repo_label} from the local database.[/]\n"
        )
        return

    console.print("[bold yellow][!] Search finished. 0 records found in the local database for these categories.[/]\n")


def display_summary(user_query: str, target_categories: List[str], db_data: list, console: Console) -> None:
    if not target_categories:
        console.print(f"[bold yellow]There are currently {len(AVAILABLE_CATEGORIES)} tracked API signature categories in the system.[/]")
        return

    matches = collect_matches(target_categories, db_data)
    repo_count = len({match["repo"] for match in matches})
    scope_label = describe_scope(user_query, target_categories)

    summary_table = Table(title="[bold cyan]API Sniffer Summary[/]", border_style="cyan", expand=False)
    summary_table.add_column("Metric", style="yellow")
    summary_table.add_column("Value", style="green", justify="right")
    summary_table.add_row("Scope", scope_label)
    summary_table.add_row("Repositories with matches", str(repo_count))
    summary_table.add_row("Matching findings in local DB", str(len(matches)))
    summary_table.add_row("Tracked categories", str(len(target_categories)))

    console.print(summary_table)
    console.print(f"[dim]Categories: {', '.join(target_categories)}[/]\n")


def fallback_understanding(user_query: str, target_categories: List[str], summary_mode: bool) -> str:
    if not target_categories:
        if summary_mode:
            return "You are asking about the available signature categories."
        return "I could not confidently map that request to known signature categories."
    scope_label = describe_scope(user_query, target_categories)
    if summary_mode:
        return f"You are asking about {scope_label}."
    return f"You are looking for {scope_label}."


def process_query(cleaned_input: str, api_key: str, db_data: list, console: Console) -> None:
    local_categories = infer_categories_from_query(cleaned_input)

    with console.status("[bold yellow]AI is thinking...[/]", spinner="dots"):
        ai_route = normalize_ai_route(ask_ai_for_pointers(cleaned_input, api_key, console))

    target_categories = normalize_categories(local_categories + ai_route["target_categories"])
    summary_mode = is_summary_query(cleaned_input) or ai_route["intent"] == "summary"
    understanding = ai_route["understanding"] or fallback_understanding(cleaned_input, target_categories, summary_mode)

    console.print(f"[bold green]AI:[/] {understanding}")

    if summary_mode:
        display_summary(cleaned_input, target_categories, db_data, console)
        return

    search_and_display(target_categories, db_data, console)


def run_single_query(
    query_text: str,
    console: Optional[Console] = None,
    show_header: bool = False,
    api_key: Optional[str] = None,
) -> None:
    active_console = console or Console()
    cleaned_query = query_text.strip()
    if not cleaned_query:
        return

    if show_header:
        render_header(active_console)

    resolved_api_key = api_key or get_groq_api_key(active_console)
    db_data = load_database(active_console)
    if not db_data:
        return

    if show_header:
        render_database_overview(active_console, db_data)

    process_query(cleaned_query, resolved_api_key, db_data, active_console)


def run_interactive_search(console: Optional[Console] = None) -> None:
    active_console = console or Console()
    render_header(active_console)

    api_key = get_groq_api_key(active_console)
    db_data = load_database(active_console)
    if not db_data:
        return

    render_database_overview(active_console, db_data)
    active_console.print("[dim]Type 'exit' or 'quit' to close the terminal.[/]\n")

    while True:
        try:
            user_input = Prompt.ask("[bold cyan]Ask AI[/]", console=active_console)
            cleaned_input = user_input.strip()
            if not cleaned_input:
                continue

            if cleaned_input.lower() in {"exit", "quit"}:
                active_console.print("[bold magenta]Shutting down AI Engine...[/]")
                break

            process_query(cleaned_input, api_key, db_data, active_console)
        except KeyboardInterrupt:
            active_console.print("\n[bold magenta]Shutting down AI Engine...[/]")
            break
        except Exception as error:
            active_console.print(f"[bold red]Unexpected Error: {error}[/]")
