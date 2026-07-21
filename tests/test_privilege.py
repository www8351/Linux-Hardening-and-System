"""Tests for ossys.privilege — the two automation paths.

Covers mode detection for root / sudo / user, the non-interactive guarantees (`sudo -n`,
timeout, closed stdin), absolute-path pinning, and the minimal environment. Every external
command is mocked; nothing is executed."""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from ossys import privilege
from ossys.exits import ExternalCommandError, PermissionDenied
from ossys.privilege import PrivMode, build_argv, detect_mode, run, safe_env


@pytest.fixture
def posix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ossys.privilege.os.name", "posix")


def _set_euid(monkeypatch: pytest.MonkeyPatch, value: int) -> None:
    monkeypatch.setattr("ossys.privilege.os.geteuid", lambda: value, raising=False)


def test_detect_root(monkeypatch: pytest.MonkeyPatch, posix: None) -> None:
    _set_euid(monkeypatch, 0)
    report = detect_mode()
    assert report.mode is PrivMode.ROOT
    assert "euid 0" in report.reason


def test_detect_sudo_when_passwordless_available(
    monkeypatch: pytest.MonkeyPatch, posix: None
) -> None:
    _set_euid(monkeypatch, 1000)
    monkeypatch.setattr(privilege, "probe_sudo", lambda timeout=5.0: ("/usr/bin/sudo", True))
    report = detect_mode()
    assert report.mode is PrivMode.SUDO
    assert report.sudo_noninteractive is True


def test_detect_user_when_sudo_needs_password(monkeypatch: pytest.MonkeyPatch, posix: None) -> None:
    """The unprivileged path. A password-requiring sudo is NOT an elevation route."""
    _set_euid(monkeypatch, 1000)
    monkeypatch.setattr(privilege, "probe_sudo", lambda timeout=5.0: ("/usr/bin/sudo", False))
    report = detect_mode()
    assert report.mode is PrivMode.USER
    assert "password" in report.reason


def test_detect_user_when_sudo_absent(monkeypatch: pytest.MonkeyPatch, posix: None) -> None:
    _set_euid(monkeypatch, 1000)
    monkeypatch.setattr(privilege, "probe_sudo", lambda timeout=5.0: (None, False))
    report = detect_mode()
    assert report.mode is PrivMode.USER
    assert "not installed" in report.reason


def test_detect_non_posix_is_user(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ossys.privilege.os.name", "nt")
    assert detect_mode().mode is PrivMode.USER


def test_forced_root_fails_loudly_when_not_root(
    monkeypatch: pytest.MonkeyPatch, posix: None
) -> None:
    """A forced mode that cannot hold is a config error, never a silent downgrade.

    Silently degrading would change what a scheduled unit actually does without the unit
    file changing — the operator would never know.
    """
    _set_euid(monkeypatch, 1000)
    with pytest.raises(PermissionDenied, match="not 0"):
        detect_mode("root")


def test_forced_sudo_fails_loudly_when_unavailable(
    monkeypatch: pytest.MonkeyPatch, posix: None
) -> None:
    _set_euid(monkeypatch, 1000)
    monkeypatch.setattr(privilege, "probe_sudo", lambda timeout=5.0: (None, False))
    with pytest.raises(PermissionDenied, match="NOPASSWD"):
        detect_mode("sudo")


def test_forced_unknown_mode_rejected(posix: None) -> None:
    with pytest.raises(PermissionDenied, match="unknown privilege mode"):
        detect_mode("superuser")


def test_build_argv_root_has_no_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ossys.privilege.shutil.which", lambda t: f"/usr/sbin/{t}")
    assert build_argv(["useradd", "bob"], mode=PrivMode.ROOT) == ["/usr/sbin/useradd", "bob"]


def test_build_argv_sudo_uses_dash_n(monkeypatch: pytest.MonkeyPatch) -> None:
    """`-n` is load-bearing: without it sudo prompts and the job hangs (OSSYS-SEC-006)."""
    monkeypatch.setattr("ossys.privilege.shutil.which", lambda t: f"/usr/sbin/{t}")
    monkeypatch.setattr(privilege, "probe_sudo", lambda timeout=5.0: ("/usr/bin/sudo", True))
    assert build_argv(["useradd", "bob"], mode=PrivMode.SUDO) == [
        "/usr/bin/sudo",
        "-n",
        "/usr/sbin/useradd",
        "bob",
    ]


def test_build_argv_user_mode_refuses() -> None:
    with pytest.raises(PermissionDenied):
        build_argv(["useradd", "bob"], mode=PrivMode.USER)


def test_run_is_non_interactive_and_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every call must close stdin, set a timeout, and never spawn a shell."""
    seen: dict[str, Any] = {}

    def _run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen.update(kwargs)
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("ossys.privilege.subprocess.run", _run)
    monkeypatch.setattr("ossys.privilege.shutil.which", lambda t: f"/usr/sbin/{t}")

    run(["useradd", "bob"], mode=PrivMode.ROOT, timeout=12.0)

    assert seen["stdin"] is subprocess.DEVNULL
    assert seen["timeout"] == 12.0
    assert "shell" not in seen or seen["shell"] is False
    assert seen["cmd"][0].startswith("/")


def test_run_maps_timeout_to_external_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _run(cmd: list[str], **kwargs: Any) -> None:
        raise subprocess.TimeoutExpired(cmd, 5)

    monkeypatch.setattr("ossys.privilege.subprocess.run", _run)
    monkeypatch.setattr("ossys.privilege.shutil.which", lambda t: f"/usr/sbin/{t}")

    with pytest.raises(ExternalCommandError, match="timed out") as exc:
        run(["useradd", "bob"], mode=PrivMode.ROOT, timeout=5.0)
    assert exc.value.exit_code == 30


def test_run_maps_nonzero_exit_to_external_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 9, stdout="", stderr="useradd: user exists")

    monkeypatch.setattr("ossys.privilege.subprocess.run", _run)
    monkeypatch.setattr("ossys.privilege.shutil.which", lambda t: f"/usr/sbin/{t}")

    with pytest.raises(ExternalCommandError) as exc:
        run(["useradd", "bob"], mode=PrivMode.ROOT)
    assert exc.value.exit_code == 30
    assert "user exists" in (exc.value.detail or "")


def test_run_dry_run_executes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("subprocess must not run under dry_run")

    monkeypatch.setattr("ossys.privilege.subprocess.run", _boom)
    monkeypatch.setattr("ossys.privilege.shutil.which", lambda t: f"/usr/sbin/{t}")

    proc = run(["useradd", "bob"], mode=PrivMode.ROOT, dry_run=True)
    assert proc.returncode == 0


def test_safe_env_excludes_injection_vectors(monkeypatch: pytest.MonkeyPatch) -> None:
    """OSSYS-SEC-010: LD_PRELOAD and friends must not cross into an elevated child."""
    monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
    monkeypatch.setenv("IFS", "x")
    monkeypatch.setenv("PYTHONPATH", "/tmp/evil")

    env = safe_env()

    assert "LD_PRELOAD" not in env
    assert "IFS" not in env
    assert "PYTHONPATH" not in env
    assert env["PATH"].startswith("/usr/local/sbin")


def test_require_tool_reports_missing_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ossys.privilege.shutil.which", lambda t: None)
    with pytest.raises(ExternalCommandError, match="not found on PATH"):
        privilege.require_tool("useradd")
