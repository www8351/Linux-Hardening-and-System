"""Module:   ossys.system

Purpose:  Privileged, Linux-only system operations (user provisioning) implemented as
          shell-free ``subprocess`` calls.

Usage:    from ossys.system import add_user
          add_user("alice", sudo_group=True)   # creates the user, adds it to `sudo`

Security notes:
    * The original code built commands with ``os.system('sudo useradd ' + name)`` — a
      textbook shell-injection hole: a username like ``"bob; rm -rf /"`` would be parsed
      and executed by ``/bin/sh`` as two commands.
    * Here every external command is passed to ``subprocess.run`` as an *argument list*.
      No shell is ever spawned (``shell=True`` is never used), so user input can never be
      reinterpreted as shell syntax — it is always a single, literal argv entry.
    * Defense in depth: ``validate_username`` rejects anything outside a strict allow-list
      pattern *before* the value reaches subprocess at all.
    * Least privilege: ``sudo`` is prefixed only when needed, and group escalation happens
      only when the caller explicitly opts in via ``sudo_group``.
"""

from __future__ import annotations

import re
import shutil
import subprocess

# Conservative POSIX-ish username allow-list, anchored end-to-end:
#   * must start with a lowercase letter or underscore (no leading digits/dashes),
#   * may contain lowercase letters, digits, underscores and hyphens,
#   * capped at 32 chars total (1 + up to 31) to match common useradd limits.
# Anchoring (^...$) plus the length bound means the pattern cannot be bypassed with
# embedded newlines or trailing shell metacharacters.
_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class SystemError_(RuntimeError):
    """Raised when a privileged command fails or a required system tool is missing."""


def _require(tool: str) -> str:
    """Resolve ``tool`` on ``PATH`` or fail loudly.

    Checking for the binary up front turns a confusing ``FileNotFoundError`` from
    subprocess into an explicit, actionable error (and avoids partial state where, e.g.,
    ``useradd`` succeeds but ``usermod`` is missing).
    """
    path = shutil.which(tool)
    if path is None:
        raise SystemError_(f"required tool not found: {tool}")
    return path


def validate_username(username: str) -> str:
    """Return ``username`` unchanged if it matches the strict allow-list, else raise.

    This is the trust boundary: callers must route any externally supplied username
    through here before it is used in a privileged command.
    """
    if not _USERNAME_RE.match(username):
        raise ValueError(f"invalid username: {username!r}")
    return username


def add_user(username: str, *, sudo_group: bool = False, use_sudo: bool = True) -> None:
    """Create a system user, optionally adding it to the ``sudo`` group.

    Linux only. The username is validated first, then every command is invoked with an
    argument list (never a shell string).

    Args:
        username:   The login name to create; validated against the allow-list.
        sudo_group: When True, also add the new user to the ``sudo`` group.
        use_sudo:   Prefix commands with ``sudo``; set False if already running as root.
    """
    # Trust boundary: reject malicious / malformed input before touching the system.
    validate_username(username)
    prefix = ["sudo"] if use_sudo else []

    # Create the account. List args => the username is a single literal argv entry.
    _require("useradd")
    subprocess.run([*prefix, "useradd", username], check=True)

    # Optional, opt-in privilege escalation: add the user to the `sudo` group.
    if sudo_group:
        _require("usermod")
        subprocess.run([*prefix, "usermod", "-aG", "sudo", username], check=True)
