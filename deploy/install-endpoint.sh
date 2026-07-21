#!/usr/bin/env bash
#
# Script:   deploy/install-endpoint.sh
#
# Purpose:  Install ossys onto one endpoint on either automation path, then verify the
#           install with `ossys check` before anything is armed.
#
# Usage:    ./deploy/install-endpoint.sh --path system  [--profile server]      # needs root
#           ./deploy/install-endpoint.sh --path user    [--profile workstation] # no root
#           ./deploy/install-endpoint.sh --path auto                            # pick for me
#
#           --scheduler systemd|cron|none   (default: systemd if available, else cron)
#           --dry-run                       print what would happen, touch nothing
#
# The two paths, and why they differ:
#
#   system  venv  /opt/ossys                    config  /etc/ossys/ossys.toml
#           units /etc/systemd/system           cron    /etc/cron.d/ossys
#           Runs as root. Requires root to install.
#
#   user    venv  ~/.local/share/ossys/venv     config  ~/.config/ossys/ossys.toml
#           units ~/.config/systemd/user        cron    the user's own crontab
#           Runs as the invoking user. Never touches anything outside $HOME.
#
# Nothing is enabled until the checkup passes. An endpoint that cannot pass its own
# preflight should not be running a timer.
#
set -euo pipefail

log() { printf '[install] %s\n' "$*" >&2; }
die() {
	log "ERROR: $*"
	exit 1
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PATH_MODE="auto"
PROFILE=""
SCHEDULER=""
DRY_RUN=""

while [[ $# -gt 0 ]]; do
	case "$1" in
	--path)
		PATH_MODE="${2:?--path needs a value}"
		shift 2
		;;
	--profile)
		PROFILE="${2:?--profile needs a value}"
		shift 2
		;;
	--scheduler)
		SCHEDULER="${2:?--scheduler needs a value}"
		shift 2
		;;
	--dry-run)
		DRY_RUN=1
		shift
		;;
	-h | --help)
		sed -n '2,30p' "${BASH_SOURCE[0]}"
		exit 0
		;;
	*) die "unknown argument: $1" ;;
	esac
done

run() {
	if [[ -n "$DRY_RUN" ]]; then
		log "DRY-RUN: $*"
	else
		"$@"
	fi
}

# --- Decide the path --------------------------------------------------------------------
if [[ "$PATH_MODE" == "auto" ]]; then
	if [[ "$(id -u)" -eq 0 ]]; then
		PATH_MODE="system"
	else
		PATH_MODE="user"
	fi
	log "auto-selected path: ${PATH_MODE}"
fi

case "$PATH_MODE" in
system)
	[[ "$(id -u)" -eq 0 ]] || die "--path system requires root (re-run with sudo)"
	VENV=/opt/ossys
	CONFIG_DIR=/etc/ossys
	UNIT_DIR=/etc/systemd/system
	LIB_DIR=/usr/local/lib/ossys
	: "${PROFILE:=server}"
	;;
user)
	VENV="$HOME/.local/share/ossys/venv"
	CONFIG_DIR="$HOME/.config/ossys"
	UNIT_DIR="$HOME/.config/systemd/user"
	LIB_DIR="$HOME/.local/lib/ossys"
	: "${PROFILE:=workstation}"
	;;
*) die "--path must be 'system', 'user' or 'auto'" ;;
esac

log "path=${PATH_MODE} profile=${PROFILE} venv=${VENV} config=${CONFIG_DIR}"

# --- Scheduler --------------------------------------------------------------------------
if [[ -z "$SCHEDULER" ]]; then
	if command -v systemctl >/dev/null 2>&1; then SCHEDULER=systemd; else SCHEDULER=cron; fi
	log "auto-selected scheduler: ${SCHEDULER}"
fi

# --- Install the package ----------------------------------------------------------------
command -v python3 >/dev/null 2>&1 || die "python3 not found"

log "creating venv at ${VENV}"
run mkdir -p "$(dirname "$VENV")"
run python3 -m venv "$VENV"
run "$VENV/bin/python" -m pip install --quiet --upgrade pip
run "$VENV/bin/python" -m pip install --quiet "$REPO_ROOT"

# --- Config ------------------------------------------------------------------------------
log "installing config to ${CONFIG_DIR}/ossys.toml"
run mkdir -p "$CONFIG_DIR"
if [[ -f "$CONFIG_DIR/ossys.toml" ]]; then
	log "config already exists — leaving it untouched (delete it to reinstall the example)"
else
	# 0644, not 0666: the config is policy. A world-writable policy file lets any local user
	# widen allowed_roots or flip mode, which would undo the containment this whole layer
	# exists to provide.
	run install -m 0644 "$REPO_ROOT/deploy/ossys.toml.example" "$CONFIG_DIR/ossys.toml"
fi

# --- Wrapper ------------------------------------------------------------------------------
log "installing wrapper to ${LIB_DIR}/ossys-run.sh"
run mkdir -p "$LIB_DIR"
run install -m 0755 "$REPO_ROOT/scripts/ossys-run.sh" "$LIB_DIR/ossys-run.sh"

# --- Verify BEFORE arming -----------------------------------------------------------------
# This ordering is the point of the script. Enabling a timer on an endpoint that fails its
# own checkup just schedules a recurring failure.
log "running preflight checkup..."
if [[ -n "$DRY_RUN" ]]; then
	log "DRY-RUN: ${VENV}/bin/python -m ossys --profile ${PROFILE} check"
else
	set +e
	"$VENV/bin/python" -m ossys --profile "$PROFILE" check
	rc=$?
	set -e
	if [[ $rc -ne 0 ]]; then
		log "checkup FAILED (exit ${rc}) — install left in place, scheduler NOT enabled"
		log "fix the reported items, then re-run with --scheduler ${SCHEDULER}"
		exit "$rc"
	fi
fi
log "checkup passed"

# --- Arm the scheduler ---------------------------------------------------------------------
case "$SCHEDULER" in
systemd)
	if [[ "$PATH_MODE" == "system" ]]; then
		run mkdir -p "$UNIT_DIR"
		run install -m 0644 "$REPO_ROOT/deploy/systemd/ossys-system.service" "$UNIT_DIR/"
		run install -m 0644 "$REPO_ROOT/deploy/systemd/ossys-system.timer" "$UNIT_DIR/"
		run systemctl daemon-reload
		run systemctl enable --now ossys-system.timer
		log "enabled ossys-system.timer — check with: systemctl list-timers ossys-system.timer"
	else
		run mkdir -p "$UNIT_DIR"
		run install -m 0644 "$REPO_ROOT/deploy/systemd/ossys-user.service" "$UNIT_DIR/"
		run install -m 0644 "$REPO_ROOT/deploy/systemd/ossys-user.timer" "$UNIT_DIR/"
		run systemctl --user daemon-reload
		run systemctl --user enable --now ossys-user.timer
		log "enabled ossys-user.timer — check with: systemctl --user list-timers"
		log "NOTE: for runs without an active login session, enable lingering:"
		log "      sudo loginctl enable-linger \"\$USER\""
	fi
	;;
cron)
	if [[ "$PATH_MODE" == "system" ]]; then
		run install -m 0644 "$REPO_ROOT/deploy/cron/ossys-root.cron" /etc/cron.d/ossys
		log "installed /etc/cron.d/ossys"
	else
		log "review and append deploy/cron/ossys-user.cron to your crontab:"
		log "  crontab -e"
	fi
	;;
none)
	log "scheduler setup skipped (--scheduler none)"
	;;
*) die "--scheduler must be systemd, cron or none" ;;
esac

log "done. Verify anytime with:"
log "  ${VENV}/bin/python -m ossys --profile ${PROFILE} check --strict"
