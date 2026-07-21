"""Tests for ossys.system. Proves the security contract: usernames are validated, commands
are issued as shell-free argument lists with **resolved absolute paths**, tools are
pre-flighted before any mutation, and injection attempts are rejected.

subprocess is fully mocked, so no real system user is ever created."""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from ossys import privilege, system
from ossys.exits import AlreadyDone, ExternalCommandError, PermissionDenied, ValidationError
from ossys.privilege import PrivMode


@pytest.fixture(autouse=True)
def _linux(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend to be Linux so the platform guard (OSSYS-SEC-011) does not short-circuit."""
    monkeypatch.setattr("ossys.system.sys.platform", "linux")


@pytest.fixture
def fake_run(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Record every argv that would have been executed, and execute nothing."""
    calls: list[list[str]] = []

    def _run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("ossys.privilege.subprocess.run", _run)
    monkeypatch.setattr("ossys.privilege.shutil.which", lambda tool: f"/usr/sbin/{tool}")
    monkeypatch.setattr(system, "user_exists", lambda name: False)
    return calls


def test_validate_username_accepts_valid() -> None:
    assert system.validate_username("refael") == "refael"


@pytest.mark.parametrize("bad", ["bob; rm -rf /", "Bob", "1abc", "", "a" * 40])
def test_validate_username_rejects_bad(bad: str) -> None:
    with pytest.raises(ValidationError):
        system.validate_username(bad)


def test_add_user_uses_resolved_absolute_paths(fake_run: list[list[str]]) -> None:
    """OSSYS-SEC-005: the resolved path must be *executed*, not merely checked.

    Asserting on exact argv is deliberate — a regression to string building or to bare tool
    names breaks this test rather than passing quietly.
    """
    result = system.add_user("refael", mode=PrivMode.ROOT, sudo_group=True)

    assert fake_run == [
        ["/usr/sbin/useradd", "refael"],
        ["/usr/sbin/usermod", "-aG", "sudo", "refael"],
    ]
    assert result.created is True
    assert result.sudo_group is True


def test_add_user_sudo_mode_prefixes_non_interactive_sudo(
    monkeypatch: pytest.MonkeyPatch, fake_run: list[list[str]]
) -> None:
    """OSSYS-SEC-006: `-n` is what stops sudo prompting and hanging a cron job forever."""
    monkeypatch.setattr(privilege, "probe_sudo", lambda timeout=5.0: ("/usr/bin/sudo", True))

    system.add_user("refael", mode=PrivMode.SUDO)

    assert fake_run == [["/usr/bin/sudo", "-n", "/usr/sbin/useradd", "refael"]]


def test_add_user_refuses_in_user_mode(fake_run: list[list[str]]) -> None:
    """The unprivileged automation path must refuse cleanly, not fail halfway."""
    with pytest.raises(PermissionDenied):
        system.add_user("refael", mode=PrivMode.USER)
    assert fake_run == []


def test_add_user_rejects_injection(fake_run: list[list[str]]) -> None:
    with pytest.raises(ValidationError):
        system.add_user("bob; rm -rf /", mode=PrivMode.ROOT)
    assert fake_run == []


def test_add_user_missing_tool(monkeypatch: pytest.MonkeyPatch, fake_run: list[list[str]]) -> None:
    monkeypatch.setattr("ossys.privilege.shutil.which", lambda tool: None)
    with pytest.raises(ExternalCommandError):
        system.add_user("refael", mode=PrivMode.ROOT)


def test_add_user_preflights_all_tools_before_mutating(
    monkeypatch: pytest.MonkeyPatch, fake_run: list[list[str]]
) -> None:
    """OSSYS-SEC-007: usermod was checked *after* useradd had created the account.

    On a host without usermod that left a real user behind plus a non-zero exit — a caller
    reading failure as "nothing happened" was wrong.
    """
    monkeypatch.setattr(
        "ossys.privilege.shutil.which",
        lambda tool: None if tool == "usermod" else f"/usr/sbin/{tool}",
    )

    with pytest.raises(ExternalCommandError):
        system.add_user("refael", mode=PrivMode.ROOT, sudo_group=True)

    assert fake_run == [], "useradd must not run when usermod is missing"


def test_add_user_is_idempotent(monkeypatch: pytest.MonkeyPatch, fake_run: list[list[str]]) -> None:
    """Re-running a scheduled job must be a no-op, not an error."""
    monkeypatch.setattr(system, "user_exists", lambda name: True)

    with pytest.raises(AlreadyDone) as exc:
        system.add_user("refael", mode=PrivMode.ROOT)

    assert exc.value.exit_code == 40
    assert fake_run == []


def test_add_user_dry_run_executes_nothing(fake_run: list[list[str]]) -> None:
    result = system.add_user("refael", mode=PrivMode.ROOT, dry_run=True)
    assert result.dry_run is True
    assert fake_run == []


def test_add_user_rejects_non_linux(
    monkeypatch: pytest.MonkeyPatch, fake_run: list[list[str]]
) -> None:
    """OSSYS-SEC-011: previously surfaced as a confusing missing-binary error."""
    monkeypatch.setattr("ossys.system.sys.platform", "win32")
    with pytest.raises(PermissionDenied, match="Linux-only"):
        system.add_user("refael", mode=PrivMode.ROOT)
