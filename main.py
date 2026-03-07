#!/usr/bin/env python3
# ---------------------------------------------------------------------------------- #
#                            Part of the X3r0Day project.                            #
#              You are free to use, modify, and redistribute this code,              #
#          provided proper credit is given to the original project X3r0Day.          #
# ---------------------------------------------------------------------------------- #

"""
Unified launcher for X3r0Day API Sniffer toolkit.

This file links all stages together behind one TUI menu:
1. Discovery (APISniffer.py)
2. Scanner (APIScanner.py)
3. AI Search (AISearch.py)
4. Full pipeline
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / "src"

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

QUEUE_JSON = ROOT_DIR / "recent_repos.json"
LEAKS_JSON = ROOT_DIR / "leaked_keys.json"
FAILED_JSON = ROOT_DIR / "failed_repos.json"
CLEAN_JSON = ROOT_DIR / "clean_repos.json"
PROXY_TXT = ROOT_DIR / "live_proxies.txt"

STAGES: dict[str, Tuple[str, str]] = {
    "1": ("Discovery Engine", "APISniffer.py"),
    "2": ("Leak Scanner", "APIScanner.py"),
    "3": ("AI Query Engine", "AISearch.py"),
    "6": ("AI Workflow Orchestrator", "AIWorkflow.py"),
}
MANUAL_MODE_KEYWORD = "manual"
HELP_MODE_KEYWORD = "help"
HELP_CLOSE_KEY = "q"

console = Console()

try:
    import termios
except ImportError:
    termios = None


def load_optional_json_list(path: Path) -> Optional[list]:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def repo_name_from_entry(entry) -> Optional[str]:
    if not isinstance(entry, dict):
        return None

    repo_name = str(entry.get("repo") or entry.get("name") or "").strip().strip("/")
    if not repo_name:
        return None
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]
    return repo_name.lower()


def count_repo_json(path: Path) -> Optional[int]:
    data = load_optional_json_list(path)
    if data is None:
        return None

    return len({repo_name for repo_name in (repo_name_from_entry(entry) for entry in data) if repo_name})


def count_leak_findings(path: Path) -> Optional[int]:
    data = load_optional_json_list(path)
    if data is None:
        return None

    total = 0
    for entry in data:
        if not isinstance(entry, dict):
            continue
        findings = entry.get("findings", [])
        total += len(findings) if isinstance(findings, list) else int(entry.get("total_secrets", 0) or 0)
    return total


def count_nonempty_lines(path: Path) -> Optional[int]:
    if not path.exists():
        return None
    try:
        return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    except Exception:
        return 0


def status_text(value: Optional[int], label: str) -> str:
    if value is None:
        return f"[dim]{label}: N/A[/]"
    color = "green" if value > 0 else "yellow"
    return f"[{color}]{label}: {value}[/]"


def render_header() -> None:
    header = (
        "[bold magenta]X3r0Day's - API Sniffer Control Center[/]\n"
        "[dim]Discovery | Scanning | AI-Powered Query[/]"
    )
    console.print(Panel.fit(header, border_style="magenta"))


def render_status_panel() -> None:
    queue_count = count_repo_json(QUEUE_JSON)
    failed_count = count_repo_json(FAILED_JSON)
    clean_count = count_repo_json(CLEAN_JSON)
    proxy_count = count_nonempty_lines(PROXY_TXT)
    leak_repo_count = count_repo_json(LEAKS_JSON)
    leak_finding_count = count_leak_findings(LEAKS_JSON)

    status_table = Table(expand=True, border_style="cyan", title="[bold cyan]Runtime Snapshot[/]")
    status_table.add_column("Data File", style="white")
    status_table.add_column("Count", justify="right")

    status_table.add_row("Queue (recent_repos.json)", status_text(queue_count, "Targets"))
    leak_status = status_text(leak_repo_count, "Repos with leaks")
    if leak_repo_count is not None and leak_finding_count is not None:
        finding_label = "finding" if leak_finding_count == 1 else "findings"
        leak_status = f"{leak_status} [dim]({leak_finding_count} {finding_label})[/]"
    status_table.add_row("Leaks (leaked_keys.json)", leak_status)
    status_table.add_row("Clean (clean_repos.json)", status_text(clean_count, "Clean repos"))
    status_table.add_row("Failed (failed_repos.json)", status_text(failed_count, "Failed repos"))
    status_table.add_row("Proxies (live_proxies.txt)", status_text(proxy_count, "Loaded proxies"))

    console.print(status_table)


def render_menu() -> None:
    menu = Table(expand=True, border_style="green", title="[bold green]Actions[/]")
    menu.add_column("Options", style="bold white", width=7)
    menu.add_column("Actions", style="cyan")

    menu.add_row("1", "Run Discovery Engine (APISniffer)")
    menu.add_row("2", "Run Leak Scanner (APIScanner)")
    menu.add_row("3", "Run AI Query Engine (AISearch)")
    menu.add_row("4", "Run Full Pipeline (1 -> 2 -> 3)")
    menu.add_row("5", "Refresh Dashboard")
    menu.add_row("6", "Run AI Workflow Orchestrator")
    menu.add_row("0", "Exit")
    console.print(menu)


def render_launch_panel() -> None:
    console.print(
        Panel.fit(
            "[bold cyan]AI Workflow is the default launcher.[/]\n"
            "[white]Press Enter to start the AI workflow, type [bold white]Manual[/] for the manual control center, or type [bold yellow]help[/] to see how the AI workflow operates.[/]",
            border_style="cyan",
        )
    )


def show_ai_workflow_help() -> None:
    console.clear()
    render_header()

    overview_text = (
        "[bold cyan]AI Workflow is the easiest way to run the tool.[/]\n"
        "[dim]You describe what you want in plain English, and it decides whether to discover repos, scan them, search results, or chain those steps together.[/]"
    )
    console.print(Panel.fit(overview_text, title="[bold magenta]How It Works[/]", border_style="magenta"))

    workflow_table = Table(expand=True, border_style="cyan", title="[bold cyan]What Happens[/]")
    workflow_table.add_column("Step", style="bold white", width=9)
    workflow_table.add_column("What It Does", style="cyan", width=36)
    workflow_table.add_column("Why It Helps", style="green")
    workflow_table.add_row("1", "You type a normal request.", "You do not have to manually enter each steps modules.")
    workflow_table.add_row("2", "The workflow reads the request and figures out the intent.", "It can tell the difference between a scan job, a search, or a mixed task.")
    workflow_table.add_row("3", "It starts only the modules that are needed.", "For example, a search request can go straight to results without making you step through extra menus.")
    workflow_table.add_row("4", "Each module still runs in the terminal like usual.", "You keep the same live output, progress view, and findings.")
    workflow_table.add_row("5", "When it finishes, you can ask for the next task or switch to Manual mode.", "The fast path stays simple, but the manual controls are still there when you want them.")
    console.print(workflow_table)

    examples_table = Table(expand=True, border_style="green", title="[bold green]Example Requests[/]")
    examples_table.add_column("Request", style="white")
    examples_table.add_column("Likely Plan", style="yellow")
    examples_table.add_row("Start scanning fresh repos and include commit history.", "Discovery + Scanner")
    examples_table.add_row("Show all the API keys from the current results.", "AI Search")
    examples_table.add_row("Find new repos, scan them, then let me search the results.", "Discovery + Scanner + AI Search")
    console.print(examples_table)

    controls_panel = Panel.fit(
        "[bold white]Launcher Controls[/]\n"
        f"[cyan]Enter[/] Start AI Workflow right away\n"
        f"[cyan]{MANUAL_MODE_KEYWORD.title()}[/] Open the numbered manual menu\n"
        f"[cyan]{HELP_MODE_KEYWORD}[/] Open this help screen again\n"
        f"[cyan]{HELP_CLOSE_KEY}[/] Close help and go back to the launcher",
        border_style="yellow",
    )
    console.print(controls_panel)
    Prompt.ask(f"[bold cyan]Press {HELP_CLOSE_KEY} to go back[/]", choices=[HELP_CLOSE_KEY], default=HELP_CLOSE_KEY)


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


def launch_stage(stage_name: str, script_name: str) -> bool:
    target_script = SRC_DIR / script_name
    if not target_script.exists():
        console.print(
            Panel.fit(
                f"[bold red][X] Missing file:[/] {target_script}",
                border_style="red",
            )
        )
        return False

    console.print(
        Panel.fit(
            f"[bold cyan]Launching:[/] {stage_name}\n"
            f"[dim]{sys.executable} {target_script.relative_to(ROOT_DIR)}[/]",
            border_style="cyan",
        )
    )

    terminal_state = capture_terminal_state()

    try:
        run = subprocess.run(
            [sys.executable, str(target_script)],
            cwd=str(ROOT_DIR),
            check=False,
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Stage interrupted by user.[/]")
        return False
    finally:
        restore_terminal_state(terminal_state)

    if run.returncode == 0:
        console.print(f"[bold green][+] {stage_name} finished successfully.[/]")
        return True

    console.print(f"[bold red][X] {stage_name} exited with code {run.returncode}.[/]")
    return False


def run_pipeline(stages: Iterable[Tuple[str, str]]) -> None:
    console.print(
        Panel.fit(
            "[bold magenta]Starting full pipeline[/]\n"
            "[dim]Discovery -> Scanner -> AI Query[/]",
            border_style="magenta",
        )
    )
    for stage_name, script_name in stages:
        ok = launch_stage(stage_name, script_name)
        if not ok:
            console.print("[bold red][X] Pipeline halted due to stage failure/interruption.[/]")
            return
    console.print("[bold green][+] Full pipeline complete.[/]")


def wait_for_user() -> None:
    Prompt.ask("[dim]Press Enter to return to menu[/]", default="")


def prompt_start_mode() -> bool:
    while True:
        console.clear()
        render_header()
        render_status_panel()
        render_launch_panel()

        choice = Prompt.ask("[bold cyan]Launch mode[/]", default="")
        normalized_choice = choice.strip().lower()

        if normalized_choice == HELP_MODE_KEYWORD:
            show_ai_workflow_help()
            continue

        return normalized_choice == MANUAL_MODE_KEYWORD


def run_manual_control_center() -> None:
    while True:
        console.clear()
        render_header()
        render_status_panel()
        render_menu()

        choice = Prompt.ask(
            "[bold cyan]Select option[/]",
            choices=["1", "2", "3", "4", "5", "6", "0"],
            default="5",
        )

        if choice == "0":
            console.print("[bold magenta]Exiting control center...[/]")
            break

        if choice in STAGES:
            stage_name, script_name = STAGES[choice]
            launch_stage(stage_name, script_name)
            wait_for_user()
            continue

        if choice == "4":
            run_pipeline([STAGES["1"], STAGES["2"], STAGES["3"]])
            wait_for_user()
            continue


def main() -> None:
    if not prompt_start_mode():
        stage_name, script_name = STAGES["6"]
        launch_stage(stage_name, script_name)
        return

    run_manual_control_center()


if __name__ == "__main__":
    main()
