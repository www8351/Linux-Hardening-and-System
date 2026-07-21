"""Module:   ossys.system

Purpose:  Privileged, Linux-only system operations (user provisioning) executed through the
          endpoint's privilege layer — shell-free, bounded, and idempotent.

Usage:    from ossys.system import add_user
          from ossys.privilege import detect_mode
          result = add_user("alice", mode=detect_mode().mode, sudo_group=True)

Security notes:
    * The original code built commands with ``os.system('sudo useradd ' + name)`` — a
      textbook shell-injection hole: a username like ``"bob; rm -rf /"`` would be parsed
      and executed by ``/bin/sh`` as two commands. That class is closed: every external
      command is an argv list, no shell is ever spawned, and the executable is pinned to an
      absolute resolved path (see ossys.privilege).
    * Defence in depth: ``validate_username`` rejects anything outside a strict allow-list
      *before* the value reaches subprocess at all.
    * OSSYS-SEC-005 — tool paths resolved by ``require_tools`` are now *used*, not merely
      checked and discarded, so PATH cannot be re-resolved to a different binary between
      the check and the exec.
    * OSSYS-SEC-007 — every tool the requested operation needs is resolved before the first
      mutating call, so a host missing ``usermod`` fails cleanly instead of leaving a
      created-but-ungrouped account behind.
    * OSSYS-SEC-006 — calls are bounded by a timeout with stdin closed, so a sudo password
      prompt fails fast instead of hanging a cron job forever.
    * OSSYS-SEC-011 — the platform is checked explicitly rather than being discovered
      indirectly via a missing binary.
    * Idempotency: creating a user that already exists is a no-op (Exit.NOOP), not an error.
      Schedulers re-run; an operation that fails the second time is not automatable.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from .exits import AlreadyDone, PermissionDenied
from .privilege import DEFAULT_TIMEOUT, PrivMode, require_tools, run
from .validate import validate_username

# Retained for backwards compatibility with callers/tests that imported it from here before
# validation was centralised in ossys.validate (DECISIONS.md D-004).
__all__ = ["SystemError_", "UserResult", "add_user", "user_exists", "validate_username"]


class SystemError_(RuntimeError):
    """Deprecated alias kept so existing importers do not break.

    New code raises the ossys.exits hierarchy, which carries an exit code.
    """


@dataclass(frozen=True)
class UserResult:
    """Outcome of a user-provisioning call, structured for --json and for idempotency."""

    username: str
    created: bool
    sudo_group: bool
    already_existed: bool
    dry_run: bool


def _require_linux() -> None:
    """Fail clearly on non-Linux hosts instead of via a confusing missing-binary error."""
    if not sys.platform.startswith("linux"):
        raise PermissionDenied(
            f"user provisioning is Linux-only; this host is {sys.platform}. "
            "The unprivileged task commands (count, cubes, details, archive) still work."
        )


def user_exists(username: str) -> bool:
    """True when the account already exists on this host.

    Uses the `pwd` database directly rather than shelling out to `id` — no subprocess, no
    parsing, and it works identically whether or not elevation is available. This is the
    idempotency probe: it must be callable in USER mode, where `useradd` is not.
    """
    try:
        # POSIX-only; imported lazily so this module stays importable on Windows.
        import pwd
    except ImportError:  # non-POSIX
        return False
    try:
        pwd.getpwnam(username)  # type: ignore[attr-defined]
    except KeyError:
        return False
    return True


def add_user(
    username: str,
    *,
    mode: PrivMode,
    sudo_group: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    dry_run: bool = False,
) -> UserResult:
    """Create a system user, optionally adding it to the ``sudo`` group. Idempotent.

    Args:
        username:   The login name to create; validated against the allow-list first.
        mode:       Privilege mode resolved for this endpoint (ROOT / SUDO / USER).
        sudo_group: When True, also add the user to the ``sudo`` group.
        timeout:    Per-command timeout in seconds.
        dry_run:    Resolve and validate everything, execute nothing.

    Raises:
        ValidationError:  username failed the allow-list.
        PermissionDenied: not Linux, or no elevation route on this endpoint.
        AlreadyDone:      the account already exists (Exit.NOOP — a success outcome).
    """
    # Trust boundary: reject malicious / malformed input before touching the system.
    validate_username(username)
    _require_linux()

    if not mode.is_privileged:
        raise PermissionDenied(
            f"creating user {username!r} requires elevation, but this endpoint has no "
            "elevation route (not root, and passwordless sudo is not configured). "
            "Run `ossys check` for details."
        )

    if user_exists(username):
        raise AlreadyDone(f"user {username!r} already exists; nothing to do")

    # OSSYS-SEC-007: resolve every tool this operation will need *before* the first
    # mutating call, so the operation is all-or-nothing.
    needed = ("useradd", "usermod") if sudo_group else ("useradd",)
    tools = require_tools(*needed)

    run(
        ["useradd", username],
        mode=mode,
        timeout=timeout,
        resolved=tools["useradd"],
        dry_run=dry_run,
    )

    if sudo_group:
        run(
            ["usermod", "-aG", "sudo", username],
            mode=mode,
            timeout=timeout,
            resolved=tools["usermod"],
            dry_run=dry_run,
        )

    return UserResult(
        username=username,
        created=True,
        sudo_group=sudo_group,
        already_existed=False,
        dry_run=dry_run,
    )
