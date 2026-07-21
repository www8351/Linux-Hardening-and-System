"""Module:   ossys.privilege

Purpose:  The two automation paths. Decides *how* (or whether) ossys can elevate on this
          endpoint, and runs external commands accordingly — one path for privileged hosts,
          one for unprivileged ones, both fully non-interactive.

Usage:    from ossys.privilege import detect_mode, run
          mode = detect_mode()                    # PrivMode.ROOT | SUDO | USER
          run(["useradd", "alice"], mode=mode, timeout=30)

Design:   Three modes, resolved once at startup and carried on the runtime:

            ROOT  — euid 0. No prefix; commands run directly. This is what a systemd
                    *system* unit or a root crontab gets.
            SUDO  — not root, but `sudo -n` works without a password. Commands are prefixed
                    with `sudo -n`. This is the unattended-service-account path.
            USER  — no elevation available. Privileged commands refuse with Exit.PERMISSION
                    instead of failing halfway; unprivileged commands run normally. This is
                    what a `systemctl --user` timer or a user crontab gets.

Security notes:
    * OSSYS-SEC-006 (MED) — no call had a `timeout=`, so a `sudo` password prompt on an
      expired credential blocked forever on a TTY that does not exist, hanging cron jobs and
      systemd units indefinitely. Two independent fixes here, because either alone is
      insufficient:
        - `sudo -n` (non-interactive) makes sudo *fail* rather than prompt, and
        - `timeout=` plus `stdin=DEVNULL` bounds every call regardless of which binary is
          being run.
      The project guaranteed non-interactive operation; nothing enforced it. Now the
      runtime does.
    * OSSYS-SEC-005 (MED) — `_require()` resolved a tool with `shutil.which` and then threw
      the answer away, letting subprocess resolve the name against `PATH` a second time.
      On a host with an attacker-influenced PATH that meant the binary *verified* was not
      the binary *executed*, under sudo. Every command here is executed by its resolved
      absolute path, and `sudo` itself is resolved the same way.
    * OSSYS-SEC-010 (LOW) — the child inherited the full parent environment, carrying PATH,
      LD_PRELOAD and IFS into a possibly-root process. `run()` passes an explicit minimal
      env instead of relying on the target host's `sudoers` env_reset hygiene.
    * No `shell=True`, ever. Commands are argv lists and the first element is an absolute
      path, so there is nothing for a shell to reinterpret even if one were introduced.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum

from .exits import ExternalCommandError, PermissionDenied

# Minimal environment handed to every child process. Deliberately excludes LD_PRELOAD,
# LD_LIBRARY_PATH, IFS, PYTHON*, and anything else that can redirect execution.
_SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

DEFAULT_TIMEOUT = 30.0


class PrivMode(str, Enum):
    """How this process reaches privileged operations on this endpoint."""

    ROOT = "root"
    """Already euid 0 — run commands directly."""

    SUDO = "sudo"
    """Not root, but passwordless `sudo -n` is available."""

    USER = "user"
    """No elevation route. Unprivileged commands only."""

    @property
    def is_privileged(self) -> bool:
        """True when privileged operations can actually be attempted."""
        return self is not PrivMode.USER


@dataclass(frozen=True)
class PrivilegeReport:
    """Why `detect_mode` chose what it chose. Surfaced by `ossys check`.

    Detection that cannot explain itself is impossible to debug across a fleet — "it picked
    USER on host 47" is not actionable without the reason.
    """

    mode: PrivMode
    euid: int | None
    sudo_path: str | None
    sudo_noninteractive: bool
    reason: str


def is_posix() -> bool:
    """True on POSIX hosts. Privileged operations are Linux-only (OSSYS-SEC-011)."""
    return os.name == "posix"


def _euid() -> int | None:
    """Effective UID, or None where the concept does not exist (Windows)."""
    geteuid = getattr(os, "geteuid", None)
    return geteuid() if geteuid is not None else None


def probe_sudo(timeout: float = 5.0) -> tuple[str | None, bool]:
    """Locate `sudo` and test whether it can elevate *without* prompting.

    Returns ``(resolved_path, works_noninteractively)``.

    `sudo -n true` is the whole test: `-n` tells sudo to fail immediately rather than ask
    for a password. If it returns 0 the credential is cached or a NOPASSWD rule applies, so
    unattended elevation is genuinely available. If it returns non-zero we are in USER mode
    and must say so up front, rather than discovering it mid-operation with a half-created
    account behind us.
    """
    path = shutil.which("sudo")
    if path is None:
        return None, False
    try:
        proc = subprocess.run(  # noqa: S603 - absolute path, argv list, no shell
            [path, "-n", "true"],
            check=False,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=safe_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return path, False
    return path, proc.returncode == 0


def safe_env() -> dict[str, str]:
    """Build the minimal environment passed to child processes (OSSYS-SEC-010)."""
    env = {"PATH": _SAFE_PATH}
    for key in ("LANG", "LC_ALL", "TZ"):
        value = os.environ.get(key)
        if value is not None:
            env[key] = value
    return env


def detect_mode(prefer: str | None = None, *, timeout: float = 5.0) -> PrivilegeReport:
    """Resolve the privilege mode for this endpoint, with the reasoning attached.

    Args:
        prefer: Force a mode from config or `--mode` ("root"/"sudo"/"user"), or "auto"/None
                to detect. Forcing is validated, not trusted — asking for ROOT while not
                root is a config error the operator needs told about immediately, not a
                silent downgrade that changes what the timer actually does.
        timeout: Bound on the `sudo -n true` probe.
    """
    euid = _euid()

    if prefer and prefer != "auto":
        try:
            wanted = PrivMode(prefer)
        except ValueError as exc:
            raise PermissionDenied(
                f"unknown privilege mode {prefer!r} (expected: auto, root, sudo, user)"
            ) from exc

        if wanted is PrivMode.ROOT and euid not in (0, None):
            raise PermissionDenied(f"mode 'root' requested but effective uid is {euid}, not 0")
        if wanted is PrivMode.SUDO:
            sudo_path, ok = probe_sudo(timeout)
            if not ok:
                raise PermissionDenied(
                    "mode 'sudo' requested but passwordless `sudo -n` is unavailable; "
                    "add a NOPASSWD rule for this account or switch the endpoint to "
                    "mode = 'user'"
                )
            return PrivilegeReport(wanted, euid, sudo_path, True, "forced by configuration")
        return PrivilegeReport(wanted, euid, None, False, "forced by configuration")

    if not is_posix():
        return PrivilegeReport(
            PrivMode.USER, euid, None, False, f"non-POSIX platform ({sys.platform})"
        )

    if euid == 0:
        return PrivilegeReport(PrivMode.ROOT, euid, None, False, "running as root (euid 0)")

    sudo_path, ok = probe_sudo(timeout)
    if ok:
        return PrivilegeReport(
            PrivMode.SUDO, euid, sudo_path, True, "passwordless `sudo -n` available"
        )

    reason = "sudo not installed" if sudo_path is None else "`sudo -n` requires a password"
    return PrivilegeReport(PrivMode.USER, euid, sudo_path, False, reason)


def require_tool(tool: str) -> str:
    """Resolve ``tool`` on PATH and return its **absolute path**, or fail loudly.

    The return value is the point (OSSYS-SEC-005). Callers must execute the returned path,
    not the bare name — resolving twice against a mutable PATH means the binary checked is
    not necessarily the binary run.
    """
    path = shutil.which(tool)
    if path is None:
        raise ExternalCommandError(f"required tool not found on PATH: {tool}")
    return path


def require_tools(*tools: str) -> dict[str, str]:
    """Resolve every tool an operation will need, before any of them runs.

    OSSYS-SEC-007: `_require("usermod")` was called *after* `useradd` had already created
    the account, so a host without `usermod` ended up with a real user plus a non-zero exit
    — a caller that reasonably read failure as "nothing happened" was wrong. Pre-flighting
    the whole set makes the operation all-or-nothing.
    """
    return {tool: require_tool(tool) for tool in tools}


def build_argv(argv: list[str], *, mode: PrivMode, resolved: str | None = None) -> list[str]:
    """Prefix ``argv`` for the given privilege mode and pin the executable to an abs path.

    ROOT adds nothing; SUDO prepends `sudo -n`; USER refuses, because a privileged command
    that cannot elevate should fail before it starts rather than emit a confusing error
    from the tool itself.
    """
    if not argv:
        raise ExternalCommandError("empty command")

    if mode is PrivMode.USER:
        raise PermissionDenied(
            f"'{argv[0]}' requires elevated privileges, but no elevation route is available "
            "on this endpoint (not root, and passwordless sudo is not configured)"
        )

    exe = resolved or require_tool(argv[0])
    command = [exe, *argv[1:]]

    if mode is PrivMode.SUDO:
        sudo_path, ok = probe_sudo()
        if not ok or sudo_path is None:
            raise PermissionDenied("passwordless sudo is no longer available")
        # `-n` is load-bearing: it guarantees sudo fails instead of prompting.
        return [sudo_path, "-n", *command]

    return command


def run(
    argv: list[str],
    *,
    mode: PrivMode,
    timeout: float = DEFAULT_TIMEOUT,
    resolved: str | None = None,
    check: bool = True,
    dry_run: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Execute an external command under the endpoint's privilege mode.

    Never spawns a shell. Always bounded by ``timeout``. Always given a closed stdin, so no
    child can block waiting for input that will never arrive.
    """
    command = build_argv(argv, mode=mode, resolved=resolved)

    if dry_run:
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    try:
        proc = subprocess.run(  # noqa: S603 - argv list, absolute exe, shell=False
            command,
            check=False,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=safe_env(),
        )
    except subprocess.TimeoutExpired as exc:
        raise ExternalCommandError(
            f"command timed out after {timeout}s: {command[0]}",
            detail=" ".join(command),
        ) from exc
    except OSError as exc:
        raise ExternalCommandError(f"could not execute {command[0]}: {exc}") from exc

    if check and proc.returncode != 0:
        raise ExternalCommandError(
            f"command failed with exit {proc.returncode}: {command[0]}",
            detail=(proc.stderr or "").strip() or " ".join(command),
        )
    return proc
