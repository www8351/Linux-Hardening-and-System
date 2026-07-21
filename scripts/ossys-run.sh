#!/usr/bin/env bash
#
# Script:   scripts/ossys-run.sh
#
# Purpose:  Mode-aware wrapper for scheduled ossys runs. Works unchanged on BOTH automation
#           paths — root/sudo (privileged) and plain user (unprivileged) — and gates every
#           run behind `ossys check` so a misconfigured endpoint fails loudly at the top
#           instead of halfway through a task.
#
# Usage:    ./scripts/ossys-run.sh <command> [args...]
#           ./scripts/ossys-run.sh archive /var/log/syslog -o /var/lib/ossys/syslog.tgz
#
#           OSSYS_PROFILE=server  ./scripts/ossys-run.sh useradd alice --sudo
#           OSSYS_MODE=user       ./scripts/ossys-run.sh archive ~/.bashrc -o ~/ossys/dot.tgz
#           OSSYS_SKIP_CHECK=1    ./scripts/ossys-run.sh count 5      # bypass the gate
#           OSSYS_STRICT=1        ./scripts/ossys-run.sh archive ...  # warnings are fatal
#
# Exit codes are passed through verbatim from ossys — see `ossys.exits`:
#   0 ok · 10 validation · 20 permission · 30 external · 40 no-op · 50 config · 60 preflight
#
# Notes:    `set -euo pipefail` makes the wrapper fail fast and loudly:
#             -e  exit on any command error
#             -u  error on use of an unset variable
#             -o pipefail  surface failures anywhere in a pipeline
#           All arguments are forwarded via "$@" (array-quoted), so they are never re-split
#           or re-evaluated by the shell.
#
#           Every diagnostic in this script goes to stderr. Nothing but ossys' own output
#           reaches stdout, so `ossys-run.sh --json ... | jq` works (OSSYS-SEC-015).
#
set -euo pipefail

log() { printf '[ossys-run] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# --- Locate the interpreter -------------------------------------------------------------
# `python -m ossys` is preferred over the console script everywhere: no PATH dependency, no
# shim, and immune to the uv trampoline failure on paths containing spaces.
if [[ -n "${OSSYS_PYTHON:-}" ]]; then
	OSSYS=("$OSSYS_PYTHON" -m ossys)
elif [[ -x /opt/ossys/bin/python ]]; then
	OSSYS=(/opt/ossys/bin/python -m ossys)
elif [[ -x "$HOME/.local/share/ossys/venv/bin/python" ]]; then
	OSSYS=("$HOME/.local/share/ossys/venv/bin/python" -m ossys)
elif command -v uv >/dev/null 2>&1 && [[ -f pyproject.toml ]]; then
	OSSYS=(uv run python -m ossys)
elif command -v ossys >/dev/null 2>&1; then
	OSSYS=(ossys)
else
	die "cannot locate ossys; set OSSYS_PYTHON to a venv interpreter that has it installed"
fi

# --- Resolve the privilege path ---------------------------------------------------------
# Detection here mirrors ossys.privilege.detect_mode. It is advisory only — ossys makes the
# real decision — but reporting it in the log means a fleet operator reading a failed run
# can see which path was taken without re-running anything.
if [[ -n "${OSSYS_MODE:-}" ]]; then
	MODE="$OSSYS_MODE"
	log "privilege mode: ${MODE} (forced via OSSYS_MODE)"
elif [[ "$(id -u)" -eq 0 ]]; then
	MODE="root"
	log "privilege mode: root (euid 0) — PRIVILEGED path"
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
	MODE="sudo"
	log "privilege mode: sudo (passwordless available) — PRIVILEGED path"
else
	MODE="user"
	log "privilege mode: user (no elevation route) — UNPRIVILEGED path"
fi

ARGS=(--mode "$MODE")
[[ -n "${OSSYS_PROFILE:-}" ]] && ARGS+=(--profile "$OSSYS_PROFILE")
[[ -n "${OSSYS_CONFIG:-}" ]] && ARGS+=(--config "$OSSYS_CONFIG")
[[ -n "${OSSYS_JSON:-}" ]] && ARGS+=(--json)

# --- The checkup gate -------------------------------------------------------------------
# Run the read-only endpoint checkup before the real work. A failed checkup means the host
# cannot do the job — a missing binary, an unwritable output root, an expired sudo
# credential — and running anyway just converts a clear diagnostic into an obscure one.
if [[ -z "${OSSYS_SKIP_CHECK:-}" ]]; then
	CHECK_ARGS=("${ARGS[@]}" check)
	[[ -n "${OSSYS_STRICT:-}" ]] && CHECK_ARGS+=(--strict)

	log "running preflight checkup..."
	# Temporarily disable -e so a non-zero checkup is reported rather than killing the
	# script with no explanation.
	set +e
	"${OSSYS[@]}" "${CHECK_ARGS[@]}" >&2
	rc=$?
	set -e
	if [[ $rc -ne 0 ]]; then
		log "preflight FAILED (exit ${rc}); refusing to run '$*'"
		log "re-run '${OSSYS[*]} ${ARGS[*]} check' for details, or set OSSYS_SKIP_CHECK=1 to override"
		exit "$rc"
	fi
	log "preflight passed"
else
	log "preflight skipped (OSSYS_SKIP_CHECK set)"
fi

# --- Run the requested command ----------------------------------------------------------
[[ $# -gt 0 ]] || die "no command given; usage: $0 <command> [args...]"

log "running: $*"
set +e
"${OSSYS[@]}" "${ARGS[@]}" "$@"
rc=$?
set -e

case "$rc" in
0) log "success" ;;
40) log "no-op — already in the desired state (exit 40 is a success outcome)" ;;
10) log "validation error (exit 10) — bad input" ;;
20) log "permission denied (exit 20) — this endpoint has no elevation route" ;;
30) log "external command failed or timed out (exit 30)" ;;
50) log "configuration error (exit 50)" ;;
60) log "preflight error (exit 60)" ;;
*) log "failed with exit ${rc}" ;;
esac

exit "$rc"
