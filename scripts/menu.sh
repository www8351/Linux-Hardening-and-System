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

echo "Examples:"
echo "  $0 count 200"
echo "  $0 cubes 7 --seed 42"
echo "  $0 details --name Refael --age 30 --phone 555"
echo

# Forward all arguments straight to the CLI.
exec "${OSSYS[@]}" "$@"
