#!/usr/bin/env python3
# ---------------------------------------------------------------------------------- #
#                            Part of the X3r0Day project.                            #
#              You are free to use, modify, and redistribute this code,              #
#          provided proper credit is given to the original project X3r0Day.          #
# ---------------------------------------------------------------------------------- #

import argparse

from shared.ai_search_runtime import run_interactive_search, run_single_query


def parse_args():
    parser = argparse.ArgumentParser(description="Search the leaked keys database.")
    parser.add_argument("--query", help="Run a single AI search query and exit.")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.query:
        run_single_query(args.query, show_header=True)
        return

    run_interactive_search()


if __name__ == "__main__":
    main()