"""Tests for ossys.preflight — the endpoint checkup.

Covers the read-only contract, the ok/warn/fail severity rules for each automation path,
and the strict-mode deployment gate."""

from __future__ import annotations

from pathlib import Path

import pytest

from ossys import preflight
from ossys.config import Settings
from ossys.preflight import Check, run_checks, summarise
from ossys.privilege import PrivilegeReport, PrivMode


def _report(mode: PrivMode) -> PrivilegeReport:
    return PrivilegeReport(
        mode=mode, euid=0, sudo_path=None, sudo_noninteractive=False, reason="test"
    )


def test_run_checks_never_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The checkup must report failures as rows, not blow up — it is a diagnostic tool."""

    def _boom(prefer: str | None = None, **kwargs: object) -> PrivilegeReport:
        raise RuntimeError("detection exploded")

    monkeypatch.setattr(preflight, "detect_mode", _boom)
    settings = Settings(allowed_roots=[str(tmp_path)])

    checks = run_checks(settings)

    privilege_check = next(c for c in checks if c.name == "privilege")
    assert privilege_check.status == "fail"
    assert "exploded" in privilege_check.detail


def test_user_mode_is_a_warning_not_a_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """USER mode is a valid deployment — the unprivileged path. Flagging it red on every
    workstation would train operators to ignore the output."""
    monkeypatch.setattr(preflight, "detect_mode", lambda prefer=None: _report(PrivMode.USER))
    settings = Settings(allowed_roots=[str(tmp_path)])

    checks = run_checks(settings)
    verdict = summarise(checks)

    assert next(c for c in checks if c.name == "privilege").status == "warn"
    assert verdict["ok"] is True


def test_missing_privileged_tool_only_fails_when_elevation_exists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A workstation on the unprivileged path has no business being marked broken for
    lacking useradd."""
    monkeypatch.setattr("ossys.preflight.shutil.which", lambda tool: None)
    settings = Settings(allowed_roots=[str(tmp_path)])

    monkeypatch.setattr(preflight, "detect_mode", lambda prefer=None: _report(PrivMode.USER))
    unpriv = {c.name: c.status for c in run_checks(settings)}
    assert unpriv["tool:useradd"] == "warn"

    monkeypatch.setattr(preflight, "detect_mode", lambda prefer=None: _report(PrivMode.ROOT))
    priv = {c.name: c.status for c in run_checks(settings)}
    assert priv["tool:useradd"] == "fail"


def test_missing_allowed_root_is_a_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The most common deployment mistake: config points at a directory nobody created."""
    monkeypatch.setattr(preflight, "detect_mode", lambda prefer=None: _report(PrivMode.USER))
    settings = Settings(allowed_roots=[str(tmp_path / "does-not-exist")])

    checks = run_checks(settings)
    root_check = next(c for c in checks if c.name.startswith("root:"))

    assert root_check.status == "fail"
    assert "does not exist" in root_check.detail
    assert summarise(checks)["ok"] is False


def test_existing_writable_root_passes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(preflight, "detect_mode", lambda prefer=None: _report(PrivMode.USER))
    checks = run_checks(Settings(allowed_roots=[str(tmp_path)]))
    assert next(c for c in checks if c.name.startswith("root:")).status == "ok"


def test_config_required_tool_missing_always_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A tool the operator explicitly listed is not optional on any path."""
    monkeypatch.setattr("ossys.preflight.shutil.which", lambda tool: None)
    monkeypatch.setattr(preflight, "detect_mode", lambda prefer=None: _report(PrivMode.USER))
    settings = Settings(allowed_roots=[str(tmp_path)], require_tools=["borg"])

    checks = run_checks(settings)
    assert next(c for c in checks if c.name == "tool:borg").status == "fail"


def test_strict_promotes_warnings_to_failures() -> None:
    """The deployment gate: "sudo unavailable" on a host meant to be privileged should stop
    the rollout, not scroll past."""
    checks = [
        Check("a", "ok", ""),
        Check("b", "warn", ""),
    ]
    assert summarise(checks, strict=False)["ok"] is True
    assert summarise(checks, strict=True)["ok"] is False


def test_summary_is_json_serialisable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Fleet collection depends on this being a plain dict of primitives."""
    import json

    monkeypatch.setattr(preflight, "detect_mode", lambda prefer=None: _report(PrivMode.USER))
    verdict = summarise(run_checks(Settings(allowed_roots=[str(tmp_path)])))
    assert json.loads(json.dumps(verdict))["counts"]["fail"] == 0


def test_no_config_file_is_a_warning_not_a_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(preflight, "detect_mode", lambda prefer=None: _report(PrivMode.USER))
    checks = run_checks(Settings(allowed_roots=[str(tmp_path)]))
    assert next(c for c in checks if c.name == "config").status == "warn"
