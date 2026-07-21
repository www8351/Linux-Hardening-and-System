"""Module:   ossys.preflight

Purpose:  The endpoint checkup. Answers "is this machine actually able to run the thing the
          timer is about to run?" *before* the timer runs it — and does so read-only, so it
          is safe to schedule on every endpoint at any frequency.

Usage:    ossys check                      # human-readable table, exit 0 or 60
          ossys check --json               # machine-readable, for fleet collection
          ossys check --strict             # warnings become failures

Why this exists:
    Both automation paths fail in ways that are invisible until the scheduled run. A `sudo`
    credential expires, `useradd` is missing from a minimal container, the output directory
    the config points at was never created, a profile name is typo'd. Each of those turns
    into a 03:00 failure with a terse log line. `ossys check` moves the discovery to
    deployment time, and — because it emits structured results — lets a fleet be swept for
    misconfigured endpoints in one pass.

Security notes:
    * Read-only by construction. It resolves binaries, stats directories, and runs exactly
      one external command: `sudo -n true`, which changes nothing. Nothing here creates,
      writes, or deletes, so it is safe to run at any privilege level on a production host.
    * The writability probe deliberately uses `os.access(..., W_OK)` rather than creating a
      temp file. Creating a probe file as root inside an operator-controlled directory is
      itself a small privilege-boundary crossing, and `os.access` answers the question
      without touching the filesystem.
    * `sudo -n true` is a genuine credential test, not a heuristic, and `-n` guarantees it
      cannot hang waiting for a password (OSSYS-SEC-006).
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
import urllib.parse
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from .config import Settings
from .privilege import PrivMode, detect_mode, is_posix

Status = Literal["ok", "warn", "fail"]

# Tools each privileged operation needs. Checked as a set so a partially-provisioned host
# is reported once, up front, rather than discovered halfway through (OSSYS-SEC-007).
PRIVILEGED_TOOLS = ("useradd", "usermod")


@dataclass(frozen=True)
class Check:
    """One check result. Flat and JSON-serialisable for fleet collection."""

    name: str
    status: Status
    detail: str

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def _check(name: str, status: Status, detail: str) -> Check:
    return Check(name=name, status=status, detail=detail)


def check_python() -> Check:
    v = sys.version_info
    version = f"{v.major}.{v.minor}.{v.micro}"
    if v < (3, 10):
        return _check("python", "fail", f"{version} is below the required 3.10")
    return _check("python", "ok", version)


def check_platform() -> Check:
    """Privileged commands are Linux-only (OSSYS-SEC-011).

    A non-Linux host is a warning, not a failure: the pure task commands (count, cubes,
    details, archive) are cross-platform and genuinely useful there. Only user provisioning
    is gated.
    """
    desc = f"{platform.system()} {platform.release()}"
    if sys.platform.startswith("linux"):
        return _check("platform", "ok", desc)
    if is_posix():
        return _check("platform", "warn", f"{desc} — user provisioning is Linux-only")
    return _check("platform", "warn", f"{desc} — unprivileged commands only")


def check_privilege(settings: Settings) -> tuple[Check, PrivMode]:
    """Resolve the privilege mode and explain the choice.

    USER mode is reported as a warning rather than a failure. It is a completely valid
    deployment — the unprivileged automation path — and flagging it red on every workstation
    endpoint would train operators to ignore the output.
    """
    try:
        report = detect_mode(settings.mode)
    except Exception as exc:  # surfaced as a check result, never raised
        return _check("privilege", "fail", str(exc)), PrivMode.USER

    detail = f"{report.mode.value} — {report.reason}"
    if report.mode is PrivMode.USER:
        warned = _check("privilege", "warn", f"{detail}; privileged commands unavailable")
        return warned, report.mode
    return _check("privilege", "ok", detail), report.mode


def check_tools(settings: Settings, mode: PrivMode) -> list[Check]:
    """Resolve every binary this endpoint's operations will need.

    Missing privileged tools are only a failure when elevation is actually available —
    a workstation running the unprivileged path has no business being marked broken for
    lacking `useradd`.
    """
    results: list[Check] = []
    severity: Status = "fail" if mode.is_privileged else "warn"

    for tool in PRIVILEGED_TOOLS:
        path = shutil.which(tool)
        if path is None:
            results.append(_check(f"tool:{tool}", severity, "not found on PATH"))
        else:
            results.append(_check(f"tool:{tool}", "ok", path))

    for tool in settings.require_tools:
        path = shutil.which(tool)
        results.append(
            _check(f"tool:{tool}", "ok", path)
            if path
            else _check(f"tool:{tool}", "fail", "required by config, not found on PATH")
        )

    return results


def check_config(settings: Settings) -> Check:
    if settings.source is None:
        return _check(
            "config",
            "warn",
            "no config file found; using built-in defaults (see `ossys check --json`)",
        )
    return _check("config", "ok", f"{settings.source} [profile: {settings.profile}]")


def check_allowed_roots(settings: Settings) -> list[Check]:
    """Verify every configured output root exists and is writable.

    This is the check that catches the most common deployment mistake: a config pointing at
    /var/lib/ossys on a host where nobody created /var/lib/ossys. Without it the failure
    surfaces as a validation error inside the scheduled run, long after deployment.
    """
    results: list[Check] = []
    for raw, resolved in zip(settings.allowed_roots, settings.resolved_roots(), strict=True):
        label = f"root:{raw}"
        if not resolved.exists():
            results.append(_check(label, "fail", f"{resolved} does not exist"))
        elif not resolved.is_dir():
            results.append(_check(label, "fail", f"{resolved} is not a directory"))
        elif not os.access(resolved, os.W_OK):
            results.append(_check(label, "fail", f"{resolved} is not writable"))
        else:
            results.append(_check(label, "ok", str(resolved)))
    return results


def check_webhook(settings: Settings) -> Check:
    """Report the failure-notification posture without contacting the endpoint.

    Deliberately does NOT send a test POST: `ossys check` is read-only and safe to schedule
    at any frequency, and a checkup that fires an alert every time it runs is worse than no
    checkup. What is verified is everything that can be verified locally — scheme, host,
    absence of embedded credentials, and whether the named token env var is actually set.

    A configured token env var that is empty is a *failure*: the alert would be delivered
    unauthenticated and silently dropped by the collector, which is the failure mode where
    an operator believes alerting works and it does not.
    """
    from .notify import WebhookConfigError, validate_webhook_url

    if not settings.webhook_url:
        return _check("webhook", "ok", "not configured (no failure notifications)")
    if not settings.webhook_on_failure:
        return _check("webhook", "warn", "configured but on_failure is disabled")

    try:
        validate_webhook_url(settings.webhook_url, allow_http=settings.webhook_allow_http)
    except WebhookConfigError as exc:
        return _check("webhook", "fail", str(exc))

    host = urllib.parse.urlsplit(settings.webhook_url).hostname
    if settings.webhook_token_env and not os.environ.get(settings.webhook_token_env):
        return _check(
            "webhook",
            "fail",
            f"{host}: token_env {settings.webhook_token_env!r} is set in config but that "
            "environment variable is empty or unset",
        )

    detail = f"{host} (timeout {settings.webhook_timeout}s"
    detail += ", detail included)" if settings.webhook_include_detail else ")"
    return _check("webhook", "ok", detail)


def check_non_interactive() -> Check:
    """Confirm ossys is not attached to a terminal it might be tempted to prompt on.

    Informational: an interactive shell is the normal case for a human running `ossys check`
    by hand. It matters as a fleet signal — a *scheduled* run reporting `tty=True` means
    something is invoking ossys in a way the automation contract did not anticipate.
    """
    interactive = sys.stdin.isatty() if hasattr(sys.stdin, "isatty") else False
    return _check(
        "non_interactive",
        "ok",
        "no controlling tty (scheduled context)" if not interactive else "attached to a tty",
    )


def run_checks(settings: Settings) -> list[Check]:
    """Run the full checkup. Never raises; every failure becomes a result row."""
    checks: list[Check] = [check_python(), check_platform()]
    priv_check, mode = check_privilege(settings)
    checks.append(priv_check)
    checks.append(check_config(settings))
    checks.extend(check_allowed_roots(settings))
    checks.extend(check_tools(settings, mode))
    checks.append(check_webhook(settings))
    checks.append(check_non_interactive())
    return checks


def summarise(checks: list[Check], *, strict: bool = False) -> dict[str, Any]:
    """Reduce results to a machine-readable verdict.

    ``strict`` promotes warnings to failures — the right setting for a deployment gate,
    where "sudo is unavailable" on a host that is supposed to be privileged should stop the
    rollout rather than scroll past.
    """
    failed = [c for c in checks if c.status == "fail"]
    warned = [c for c in checks if c.status == "warn"]
    ok = not failed and (not strict or not warned)
    return {
        "ok": ok,
        "strict": strict,
        "counts": {
            "ok": sum(1 for c in checks if c.status == "ok"),
            "warn": len(warned),
            "fail": len(failed),
        },
        "checks": [asdict(c) for c in checks],
    }


def config_search_path(explicit: str | Path | None = None) -> list[str]:
    """The config discovery chain as strings — shown by `ossys check` to explain lookups."""
    from .config import candidate_paths

    return [str(p) for p in candidate_paths(explicit)]
