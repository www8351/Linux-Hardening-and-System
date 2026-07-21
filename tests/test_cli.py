"""Tests for ossys.cli — the automation contract.

These drive `main()` directly rather than Typer's CliRunner, because `main()` *is* the
exception boundary: it is what the console script and every systemd/cron invocation calls,
and it is where the exit-code taxonomy is produced. Testing the Typer app alone would leave
the entrypoint itself uncovered — which is exactly how a broken import in `main()` reached
the tree unnoticed once already."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ossys.cli import main
from ossys.exits import Exit


def invoke(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], *args: str
) -> tuple[int, str, str]:
    """Run the real entrypoint with argv and return (exit_code, stdout, stderr)."""
    monkeypatch.setattr("sys.argv", ["ossys", *args])
    code = main()
    captured = capsys.readouterr()
    return code, captured.out, captured.err


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Keep every run away from any real config on the developer's machine."""
    monkeypatch.setattr("ossys.config.candidate_paths", lambda explicit=None: [])
    monkeypatch.chdir(tmp_path)


def test_main_returns_zero_on_success(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Smoke test of the actual entrypoint — catches import-time breakage in main()."""
    code, out, _ = invoke(monkeypatch, capsys, "count", "3")
    assert code == int(Exit.OK)
    assert out.split() == ["1", "2", "3"]


def test_version_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = invoke(monkeypatch, capsys, "version")
    assert code == int(Exit.OK)
    assert out.strip()


def test_validation_error_exits_10(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The whole point of the taxonomy: bad input is distinguishable from a broken host."""
    code, _, err = invoke(monkeypatch, capsys, "count", "0")
    assert code == int(Exit.VALIDATION)
    assert "error:" in err
    assert "Traceback" not in err


def test_config_error_exits_50(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    code, _, err = invoke(
        monkeypatch, capsys, "--config", str(tmp_path / "absent.toml"), "count", "1"
    )
    assert code == int(Exit.CONFIG)
    assert "not found" in err


def test_permission_error_exits_20(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The unprivileged path refusing a privileged command."""
    monkeypatch.setattr("ossys.system.sys.platform", "linux")
    code, _, err = invoke(monkeypatch, capsys, "--mode", "user", "useradd", "alice")
    assert code == int(Exit.PERMISSION)
    assert "elevation" in err


def test_noop_exits_40(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """Idempotency: re-running a scheduled job is a success outcome with its own code."""
    monkeypatch.setattr("ossys.system.sys.platform", "linux")
    monkeypatch.setattr("ossys.system.user_exists", lambda name: True)
    code, out, _ = invoke(monkeypatch, capsys, "--mode", "root", "useradd", "alice")
    assert code == int(Exit.NOOP)
    assert "already exists" in out


def test_errors_do_not_leak_tracebacks(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """OSSYS-SEC-009: tracebacks disclosed absolute paths into CI logs and cron mail."""
    _, out, err = invoke(monkeypatch, capsys, "count", "-5")
    assert "Traceback" not in out + err
    assert 'File "' not in out + err


# --- JSON contract ----------------------------------------------------------------------


def _json_stdout(out: str) -> dict[str, Any]:
    """Parse stdout as a single JSON document. Fails loudly if anything else got mixed in."""
    parsed: dict[str, Any] = json.loads(out)
    return parsed


def test_json_success_is_parseable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = invoke(monkeypatch, capsys, "--json", "count", "3")
    payload = _json_stdout(out)
    assert code == int(Exit.OK)
    assert payload["ok"] is True
    assert payload["command"] == "count"
    assert payload["values"] == [1, 2, 3]


def test_json_failure_is_also_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An automated caller must not suddenly have to parse prose on the failure path."""
    code, out, _ = invoke(monkeypatch, capsys, "--json", "count", "0")
    payload = _json_stdout(out)
    assert code == int(Exit.VALIDATION)
    assert payload["ok"] is False
    assert payload["exit_code"] == int(Exit.VALIDATION)
    assert payload["error"] == "validation"


def test_json_mode_keeps_stdout_clean(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Nothing but the payload on stdout — the defect OSSYS-SEC-015 flagged in menu.sh."""
    _, out, _ = invoke(monkeypatch, capsys, "--json", "cubes", "2", "--seed", "1")
    assert _json_stdout(out)["command"] == "cubes"


# --- dry-run ------------------------------------------------------------------------------


def test_dry_run_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    out_file = tmp_path / "details.txt"
    code, _, _ = invoke(
        monkeypatch,
        capsys,
        "--dry-run",
        "details",
        "--name",
        "a",
        "--age",
        "1",
        "--phone",
        "2",
        "-o",
        str(out_file),
    )
    assert code == int(Exit.OK)
    assert not out_file.exists()


def test_dry_run_still_validates(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A dry run that skipped validation would be useless as a staging gate."""
    outside = tmp_path.parent / "escaped.txt"
    code, _, _ = invoke(
        monkeypatch,
        capsys,
        "--dry-run",
        "details",
        "--name",
        "a",
        "--age",
        "1",
        "--phone",
        "2",
        "-o",
        str(outside),
    )
    assert code == int(Exit.VALIDATION)


def test_details_writes_inside_cwd(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """The default allowed root is the working directory, so the normal case still works."""
    code, _, _ = invoke(
        monkeypatch,
        capsys,
        "details",
        "--name",
        "Refael",
        "--age",
        "30",
        "--phone",
        "555",
        "-o",
        "d.txt",
    )
    assert code == int(Exit.OK)
    assert "Refael" in (tmp_path / "d.txt").read_text(encoding="utf-8")


# --- checkup --------------------------------------------------------------------------------


def test_check_json_reports_structure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Fleet collection depends on this shape being stable."""
    code, out, _ = invoke(monkeypatch, capsys, "--json", "check")
    payload = _json_stdout(out)

    assert code in (int(Exit.OK), int(Exit.PREFLIGHT))
    assert isinstance(payload["checks"], list)
    assert {"name", "status", "detail"} <= set(payload["checks"][0])
    assert payload["counts"]["fail"] == 0
    assert "config_search_path" in payload


def test_check_strict_fails_on_warnings(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The deployment gate. On a non-Linux host the platform check warns, so --strict must
    turn that into a non-zero exit."""
    code, out, _ = invoke(monkeypatch, capsys, "--json", "check", "--strict")
    payload = _json_stdout(out)
    if payload["counts"]["warn"]:
        assert code == int(Exit.PREFLIGHT)
    else:
        assert code == int(Exit.OK)


def test_check_human_output_is_readable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _, out, _ = invoke(monkeypatch, capsys, "check")
    assert "[PASS]" in out
    assert "passed" in out


# --- failure webhook ------------------------------------------------------------------------


@pytest.fixture
def posted(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Intercept the webhook POST at the transport layer."""
    sent: list[dict[str, Any]] = []

    def _post(url: str, payload: dict[str, Any], *, timeout: float, token: str | None) -> int:
        sent.append({"url": url, "payload": payload})
        return 200

    monkeypatch.setattr("ossys.notify._post", _post)
    return sent


def _with_webhook(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, **extra: str) -> None:
    """Point config discovery at a temp ossys.toml carrying a webhook."""
    body = '[defaults.webhook]\nurl = "https://collector.example/hook"\n'
    for key, value in extra.items():
        body += f"{key} = {value}\n"
    cfg = tmp_path / "ossys.toml"
    cfg.write_text(body, encoding="utf-8")
    monkeypatch.setattr("ossys.config.candidate_paths", lambda explicit=None: [cfg])


def test_no_webhook_traffic_on_success(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    posted: list[dict[str, Any]],
) -> None:
    _with_webhook(monkeypatch, tmp_path)
    code, _, _ = invoke(monkeypatch, capsys, "count", "3")
    assert code == int(Exit.OK)
    assert posted == []


def test_webhook_fires_on_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    posted: list[dict[str, Any]],
) -> None:
    _with_webhook(monkeypatch, tmp_path)
    code, _, _ = invoke(monkeypatch, capsys, "count", "0")

    assert code == int(Exit.VALIDATION)
    assert len(posted) == 1
    assert posted[0]["payload"]["exit_code"] == int(Exit.VALIDATION)
    assert posted[0]["payload"]["command"] == "count"


def test_webhook_does_not_change_the_exit_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A dead collector must not turn a validation error into something else."""

    def _boom(*a: Any, **kw: Any) -> int:
        raise OSError("connection refused")

    monkeypatch.setattr("ossys.notify._post", _boom)
    _with_webhook(monkeypatch, tmp_path)

    code, _, err = invoke(monkeypatch, capsys, "count", "0")
    assert code == int(Exit.VALIDATION)
    assert "not delivered" in err


def test_webhook_suppressed_under_dry_run(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    posted: list[dict[str, Any]],
) -> None:
    outside = tmp_path.parent / "escaped.txt"
    _with_webhook(monkeypatch, tmp_path)
    code, _, _ = invoke(
        monkeypatch,
        capsys,
        "--dry-run",
        "details",
        "--name",
        "a",
        "--age",
        "1",
        "--phone",
        "2",
        "-o",
        str(outside),
    )
    assert code == int(Exit.VALIDATION)
    assert posted == []


def test_webhook_fires_on_failed_strict_checkup(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    posted: list[dict[str, Any]],
) -> None:
    """`check` exits via typer.Exit, which Typer returns rather than raises — the
    notification must still happen on that path."""
    _with_webhook(monkeypatch, tmp_path)
    code, _, _ = invoke(monkeypatch, capsys, "--json", "check", "--strict")

    if code == int(Exit.PREFLIGHT):
        assert len(posted) == 1
        assert posted[0]["payload"]["exit_code"] == int(Exit.PREFLIGHT)
    else:
        assert posted == []


def test_bad_webhook_url_is_a_config_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    cfg = tmp_path / "ossys.toml"
    cfg.write_text('[defaults.webhook]\nurl = "file:///etc/passwd"\n', encoding="utf-8")
    monkeypatch.setattr("ossys.config.candidate_paths", lambda explicit=None: [cfg])

    code, _, err = invoke(monkeypatch, capsys, "count", "3")
    assert code == int(Exit.CONFIG)
    assert "scheme" in err
