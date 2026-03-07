#!/usr/bin/env python3
# ---------------------------------------------------------------------------------- #
#                            Part of the X3r0Day project.                            #
#              You are free to use, modify, and redistribute this code,              #
#          provided proper credit is given to the original project X3r0Day.          #
# ---------------------------------------------------------------------------------- #


############################################################################################################################
#      So This code basically uses an LLM to To basically handle all the workflow which you had to do manually before      #
############################################################################################################################


# ---------------------------------------------------------------------------------- #
#                                   DISCLAIMER                                       #
# ---------------------------------------------------------------------------------- #
# This tool is part of the X3r0Day Framework and is intended for educational         #
# security research, and defensive analysis purposes only.                           #
#                                                                                    #
# The script queries publicly available GitHub repository metadata and stores it     #
# locally for further analysis. It does not exploit, access, or modify any system.   #
#                                                                                    #
# Users are solely responsible for how this software is used. The authors of the     #
# X3r0Day project do not encourage or condone misuse, unauthorized access, or any    #
# activity that violates applicable laws, regulations, or the terms of service of    #
# any platform.                                                                      #
#                                                                                    #
# Always respect platform policies, rate limits, and the privacy of developers.      #
# If you discover sensitive information or exposed credentials during research,      #
# follow responsible disclosure practices and notify the affected parties by         #
# opening **Issues**                                                                 #
#                                                                                    #
# By using this software, you acknowledge that you understand these conditions and   #
# accept full responsibility for your actions.                                       #
#                                                                                    #
# Project: X3r0Day Framework                                                         #
# Author: XeroDay                                                                    #
# ---------------------------------------------------------------------------------- #




import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from shared.ai_search_runtime import extract_json_blob, get_groq_api_key, run_single_query
from shared.category_routing import infer_categories_from_query, is_summary_query


try:
    import termios
except ImportError:
    termios = None


ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"

DISCOVERY_DEFAULTS = {
    "lookback_mins": 1,
    "chunk_mins": 1,
    "pages_to_scrape": 10,
    "proxy_retry_limit": 200,
}

SCANNER_DEFAULTS = {
    "max_threads": 15,
    "scan_commit_history": True,
    "history_depth": 10,
    "scan_heroku_keys": False,
}

ACTION_ALIASES = {
    "discovery": "discovery",
    "discover": "discovery",
    "sniffer": "discovery",
    "scanner": "scanner",
    "scan": "scanner",
    "ai_search_menu": "ai_search_menu",
    "ai_search": "ai_search_menu",
    "open_ai_menu": "ai_search_menu",
    "query_menu": "ai_search_menu",
}
WORKFLOW_TRIGGER_TERMS = ("discover", "discovery", "scan", "scanner", "pipeline", "sniff")
SEARCH_NOUN_TERMS = ("api key", "api keys", "token", "tokens", "webhook", "webhooks", "secret", "secrets", "category", "categories", "signature", "signatures")

console = Console()


def capture_terminal_state():
    if os.name == "nt" or termios is None or not sys.stdin.isatty():
        return None
    try:
        return termios.tcgetattr(sys.stdin.fileno())
    except termios.error:
        return None


def restore_terminal_state(state) -> None:
    if state is None or os.name == "nt" or termios is None or not sys.stdin.isatty():
        return
    try:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, state)
    except termios.error:
        pass


def launch_stage(stage_name: str, script_name: str, extra_args: Optional[List[str]] = None) -> bool:
    target_script = SRC_DIR / script_name
    if not target_script.exists():
        console.print(Panel.fit(f"[bold red][X] Missing stage file:[/] {target_script}", border_style="red"))
        return False

    command = [sys.executable, str(target_script), *(extra_args or [])]
    console.print(
        Panel.fit(
            f"[bold cyan]Executing:[/] {stage_name}\n[dim]{' '.join(command)}[/]",
            border_style="cyan",
        )
    )

    terminal_state = capture_terminal_state()
    try:
        completed = subprocess.run(
            command,
            cwd=str(ROOT_DIR),
            check=False,
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Workflow stage interrupted by user.[/]")
        return False
    finally:
        restore_terminal_state(terminal_state)

    if completed.returncode == 0:
        console.print(f"[bold green][+] {stage_name} finished successfully.[/]")
        return True

    console.print(f"[bold red][X] {stage_name} exited with code {completed.returncode}.[/]")
    return False


def clamp_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, number))


def normalize_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1", "on"}:
            return True
        if lowered in {"false", "no", "0", "off"}:
            return False
    return default


def normalize_action(action: Any) -> Optional[str]:
    if not isinstance(action, str):
        return None
    return ACTION_ALIASES.get(action.strip().lower())


def normalize_plan(raw_plan: Dict[str, Any]) -> Dict[str, Any]:
    normalized_steps: List[Dict[str, Any]] = []
    raw_steps = raw_plan.get("steps", [])
    if not isinstance(raw_steps, list):
        raw_steps = []

    for raw_step in raw_steps:
        if not isinstance(raw_step, dict):
            continue
        action = normalize_action(raw_step.get("action"))
        if action is None:
            continue

        params = raw_step.get("params") or {}
        if action == "discovery":
            normalized_steps.append(
                {
                    "action": action,
                    "params": {
                        "lookback_mins": clamp_int(params.get("lookback_mins"), DISCOVERY_DEFAULTS["lookback_mins"], 1, 1440),
                        "chunk_mins": clamp_int(params.get("chunk_mins"), DISCOVERY_DEFAULTS["chunk_mins"], 1, 120),
                        "pages_to_scrape": clamp_int(params.get("pages_to_scrape"), DISCOVERY_DEFAULTS["pages_to_scrape"], 1, 10),
                        "proxy_retry_limit": clamp_int(params.get("proxy_retry_limit"), DISCOVERY_DEFAULTS["proxy_retry_limit"], 1, 5000),
                    },
                }
            )
            continue

        if action == "scanner":
            normalized_steps.append(
                {
                    "action": action,
                    "params": {
                        "max_threads": clamp_int(params.get("max_threads"), SCANNER_DEFAULTS["max_threads"], 1, 128),
                        "scan_commit_history": normalize_bool(params.get("scan_commit_history"), SCANNER_DEFAULTS["scan_commit_history"]),
                        "history_depth": clamp_int(params.get("history_depth"), SCANNER_DEFAULTS["history_depth"], 1, 100),
                        "scan_heroku_keys": normalize_bool(params.get("scan_heroku_keys"), SCANNER_DEFAULTS["scan_heroku_keys"]),
                    },
                }
            )
            continue

        normalized_steps.append({"action": action, "params": {}})

    return {
        "understanding": str(raw_plan.get("understanding", "Generated workflow plan.")).strip() or "Generated workflow plan.",
        "steps": normalized_steps,
    }


def normalize_route(raw_route: Dict[str, Any]) -> Dict[str, Any]:
    normalized_plan = normalize_plan(raw_route)
    mode = str(raw_route.get("mode", "workflow")).strip().lower()
    if mode not in {"query", "workflow"}:
        mode = "workflow" if normalized_plan["steps"] else "query"
    normalized_plan["mode"] = mode
    if mode == "query":
        normalized_plan["steps"] = []
    return normalized_plan


def fallback_plan(user_request: str) -> Dict[str, Any]:
    lowered = user_request.lower()
    steps: List[Dict[str, Any]] = []

    if any(word in lowered for word in ["discover", "discovery", "sniff", "find repos"]):
        lookback = DISCOVERY_DEFAULTS["lookback_mins"]
        tokens = lowered.replace("-", " ").split()
        for idx, token in enumerate(tokens[:-1]):
            if token.isdigit() and tokens[idx + 1].startswith(("minute", "min")):
                lookback = clamp_int(token, lookback, 1, 1440)
                break
        steps.append(
            {
                "action": "discovery",
                "params": {
                    "lookback_mins": lookback,
                    "chunk_mins": DISCOVERY_DEFAULTS["chunk_mins"],
                    "pages_to_scrape": DISCOVERY_DEFAULTS["pages_to_scrape"],
                    "proxy_retry_limit": DISCOVERY_DEFAULTS["proxy_retry_limit"],
                },
            }
        )

    if any(word in lowered for word in ["scan", "scanner"]):
        max_threads = SCANNER_DEFAULTS["max_threads"]
        tokens = lowered.replace("-", " ").split()
        for idx, token in enumerate(tokens[:-1]):
            if token.isdigit() and tokens[idx + 1].startswith("thread"):
                max_threads = clamp_int(token, max_threads, 1, 128)
                break
        steps.append(
            {
                "action": "scanner",
                "params": {
                    "max_threads": max_threads,
                    "scan_commit_history": "without commit history" not in lowered and "no commit history" not in lowered,
                    "history_depth": SCANNER_DEFAULTS["history_depth"],
                    "scan_heroku_keys": "heroku" in lowered,
                },
            }
        )

    if any(phrase in lowered for phrase in ["ai menu", "ask ai", "query menu", "open ai", "ai search"]):
        steps.append({"action": "ai_search_menu", "params": {}})

    if "pipeline" in lowered and not steps:
        steps = [
            {"action": "discovery", "params": dict(DISCOVERY_DEFAULTS)},
            {"action": "scanner", "params": dict(SCANNER_DEFAULTS)},
            {"action": "ai_search_menu", "params": {}},
        ]

    return {
        "understanding": "Fallback parser generated a workflow from your request.",
        "steps": steps,
    }


def should_run_direct_query(user_request: str) -> bool:
    lowered = user_request.lower()
    if any(term in lowered for term in WORKFLOW_TRIGGER_TERMS):
        return False
    return bool(infer_categories_from_query(user_request)) or is_summary_query(user_request) or any(term in lowered for term in SEARCH_NOUN_TERMS)


def ask_ai_for_route(user_request: str, api_key: str) -> Dict[str, Any]:
    system_prompt = f"""You are X3r0Day's API Sniffer's request router.
Your job is to decide whether a user's message is:
- a query against the existing local results database
- or a workflow request that should launch discovery, scanning, or the AI search menu

You must return JSON only.

Allowed actions:
1. discovery
2. scanner
3. ai_search_menu

Defaults:
discovery = {json.dumps(DISCOVERY_DEFAULTS)}
scanner = {json.dumps(SCANNER_DEFAULTS)}

Return this exact shape:
{{
  "understanding": "One short sentence summarizing what the user wants.",
  "mode": "query",
  "steps": []
}}

or:

{{
  "understanding": "One short sentence summarizing the workflow.",
  "mode": "workflow",
  "steps": [
    {{
      "action": "discovery",
      "params": {{
        "lookback_mins": 3,
        "chunk_mins": 1,
        "pages_to_scrape": 10,
        "proxy_retry_limit": 200
      }}
    }},
    {{
      "action": "scanner",
      "params": {{
        "max_threads": 20,
        "scan_commit_history": true,
        "history_depth": 10,
        "scan_heroku_keys": false
      }}
    }},
    {{
      "action": "ai_search_menu",
      "params": {{}}
    }}
  ]
}}

Rules:
- Choose "query" when the user wants to show, list, find, search, or summarize API keys, tokens, secrets, webhooks, categories, types, or other results from the existing local database.
- Choose "query" when the user is clearly asking to see results, not to collect new data.
- Choose "workflow" only when the user is asking to discover repositories, scan repositories, run a pipeline, or open the AI search menu itself.
- Do not add discovery or scanner steps to a query request.
- If mode is "query", steps must be an empty array.
- Use only the allowed actions.
- Always include fully populated params for discovery and scanner.
- Preserve the user's order when possible.
- "open AI menu", "ask AI", or "open query engine" maps to ai_search_menu.
- If the user gives no runnable workflow, return mode "workflow" with an empty steps array.
- Examples:
  - "show me every single APIs" => mode "query"
  - "show all the API keys from the current results" => mode "query"
  - "start scanning" => mode "workflow"
  - "discover repos from the last 5 minutes and scan them" => mode "workflow"
- Do not include explanations outside the JSON."""

    payload = {
        "model": GROQ_MODEL,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_request},
        ],
        "temperature": 0,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    response = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=20)
    response.raise_for_status()
    response_json = response.json()
    return extract_json_blob(response_json["choices"][0]["message"]["content"])


def build_stage_invocation(step: Dict[str, Any]) -> Dict[str, Any]:
    action = step["action"]
    params = step["params"]

    if action == "discovery":
        return {
            "name": "Discovery Engine",
            "script": "APISniffer.py",
            "args": [
                "--lookback-mins",
                str(params["lookback_mins"]),
                "--chunk-mins",
                str(params["chunk_mins"]),
                "--pages-to-scrape",
                str(params["pages_to_scrape"]),
                "--proxy-retry-limit",
                str(params["proxy_retry_limit"]),
            ],
        }

    if action == "scanner":
        args = [
            "--max-threads",
            str(params["max_threads"]),
            "--history-depth",
            str(params["history_depth"]),
        ]
        if not params["scan_commit_history"]:
            args.append("--no-commit-history")
        if params["scan_heroku_keys"]:
            args.append("--scan-heroku-keys")
        return {
            "name": "Leak Scanner",
            "script": "APIScanner.py",
            "args": args,
        }

    return {
        "name": "AI Query Engine",
        "script": "AISearch.py",
        "args": [],
    }


def render_plan(plan: Dict[str, Any]) -> None:
    console.print(Panel.fit(f"[bold green]Workflow Understanding[/]\n{plan['understanding']}", border_style="green"))

    plan_table = Table(expand=True, border_style="magenta", title="[bold magenta]Execution Plan[/]")
    plan_table.add_column("Step", width=6, justify="right")
    plan_table.add_column("Action", style="cyan", width=18)
    plan_table.add_column("Parameters", style="white")

    for idx, step in enumerate(plan["steps"], 1):
        params = step["params"]
        if params:
            rendered_params = ", ".join(f"{key}={value}" for key, value in params.items())
        else:
            rendered_params = "-"
        plan_table.add_row(str(idx), step["action"], rendered_params)

    console.print(plan_table)


def execute_plan(plan: Dict[str, Any]) -> None:
    if not plan["steps"]:
        console.print("[bold yellow][!] No runnable workflow steps were generated.[/]")
        return

    for step in plan["steps"]:
        invocation = build_stage_invocation(step)
        ok = launch_stage(invocation["name"], invocation["script"], invocation["args"])
        if not ok:
            console.print("[bold red][X] Workflow halted because a stage failed or was interrupted.[/]")
            return

    console.print("[bold green][+] Workflow complete.[/]")


def main() -> None:
    console.print(
        Panel.fit(
            "[bold magenta]API Sniffer - AI Workflow Orchestrator[/]\n"
            "[dim]Let AI handle discovery, scanning, and query workflows[/]",
            border_style="magenta",
        )
    )
    console.print("[dim]Describe the job you want. Example: start scanning, run discovery for 3 minutes, or show all the API keys.[/]\n")

    api_key = None

    while True:
        try:
            user_input = Prompt.ask("[bold cyan]Workflow AI[/]")
            cleaned_input = user_input.strip()
            if not cleaned_input:
                continue
            if cleaned_input.lower() in {"exit", "quit"}:
                console.print("[bold magenta]Shutting down workflow orchestrator...[/]")
                break

            if api_key is None:
                api_key = get_groq_api_key(console)

            with console.status("[bold yellow]Routing request...[/]", spinner="dots"):
                try:
                    route = normalize_route(ask_ai_for_route(cleaned_input, api_key))
                except Exception as error:
                    console.print(f"[bold yellow][!] AI router fallback engaged: {error}[/]")
                    if should_run_direct_query(cleaned_input):
                        run_single_query(cleaned_input, console=console, api_key=api_key)
                        continue
                    route = normalize_route({"mode": "workflow", **fallback_plan(cleaned_input)})

            if route["mode"] == "query":
                run_single_query(cleaned_input, console=console, api_key=api_key)
                continue

            render_plan(route)
            execute_plan(route)

        except KeyboardInterrupt:
            console.print("\n[bold magenta]Shutting down workflow orchestrator...[/]")
            break
        except Exception as error:
            console.print(f"[bold red][X] Workflow orchestrator error: {error}[/]")


if __name__ == "__main__":
    main()
