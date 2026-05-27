"""Privileged system operations via subprocess with list arguments.

The original used `os.system('sudo useradd {}'.format(name))` — a shell-injection
hole. Passing an argument *list* to subprocess means the username is never
interpreted by a shell, so input like ``"bob; rm -rf /"`` is impossible to exploit.
"""

from __future__ import annotations

import re
import shutil
import subprocess

# Conservative POSIX-ish username rule.
_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class SystemError_(RuntimeError):
    """Raised when a privileged command fails or a tool is missing."""


def _require(tool: str) -> str:
    path = shutil.which(tool)
    if path is None:
        raise SystemError_(f"required tool not found: {tool}")
    return path


def validate_username(username: str) -> str:
    if not _USERNAME_RE.match(username):
        raise ValueError(f"invalid username: {username!r}")
    return username


def add_user(username: str, *, sudo_group: bool = False, use_sudo: bool = True) -> None:
    """Create a system user, optionally adding it to the sudo group.

    Linux only. Validates the username and uses list args (no shell).
    """
    validate_username(username)
    prefix = ["sudo"] if use_sudo else []

    _require("useradd")
    subprocess.run([*prefix, "useradd", username], check=True)

    if sudo_group:
        _require("usermod")
        subprocess.run([*prefix, "usermod", "-aG", "sudo", username], check=True)
