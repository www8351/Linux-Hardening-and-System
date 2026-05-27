#!/usr/bin/env bash
#
# Thin bash wrapper around the `ossys` CLI — the modern replacement for the old
# interactive menu_bash.sh. Bash still drives, but the logic lives in tested Python.
#
set -euo pipefail

# Run ossys via uv if available, else assume it is on PATH.
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
