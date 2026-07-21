#!/usr/bin/env bash
#
# Script:   scripts/menu.sh
#
# Purpose:  Thin Bash wrapper around the `ossys` CLI — the modern, non-interactive
#           replacement for the old `while true` menu_bash.sh prompt loop. Bash still
#           drives, but all logic lives in tested, validated Python.
#
# Usage:    ./scripts/menu.sh <command> [args...]
#           ./scripts/menu.sh count 200
#           ./scripts/menu.sh cubes 7 --seed 42
#           ./scripts/menu.sh details --name Refael --age 30 --phone 555
#
# Notes:    `set -euo pipefail` makes the wrapper fail fast and loudly:
#             -e  exit on any command error
#             -u  error on use of an unset variable
#             -o pipefail  surface failures anywhere in a pipeline
#           Arguments are forwarded verbatim via "$@" (array-quoted), so they are never
#           re-split or re-evaluated by the shell.
#
set -euo pipefail

# Prefer running through `uv` (reproducible, project-pinned env); otherwise fall back to a
# globally installed `ossys` on PATH.
if command -v uv >/dev/null 2>&1; then
	OSSYS=(uv run ossys)
else
	OSSYS=(ossys)
fi

# OSSYS-SEC-015: this banner used to go to stdout, ahead of the command's real output, so
# `count=$(./scripts/menu.sh count 200)` got the help text glued to its data and
# `menu.sh --json ... | jq` was unparseable. It now goes to stderr, and only when no
# arguments were given — stdout carries nothing but the CLI's own output.
if [[ $# -eq 0 ]]; then
	{
		echo "Usage: $0 <command> [args...]"
		echo
		echo "Examples:"
		echo "  $0 count 200"
		echo "  $0 cubes 7 --seed 42"
		echo "  $0 details --name Refael --age 30 --phone 555"
		echo "  $0 check --json"
		echo
		echo "For scheduled runs with a preflight gate, use scripts/ossys-run.sh instead."
	} >&2
	exec "${OSSYS[@]}" --help
fi

# Forward all arguments straight to the CLI. exec replaces this shell, so the CLI's exit
# code (see ossys.exits) reaches the caller unmodified.
exec "${OSSYS[@]}" "$@"
