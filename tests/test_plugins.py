"""Tests for ossys.plugins — entry-point auto-registration.

Entry points are faked rather than installed, so the suite exercises discovery, the
allow-list, name validation, shadow refusal and failure isolation without ever importing a
real third-party package."""

from __future__ import annotations

from typing import Any

import pytest
import typer

from ossys.config import Settings
from ossys.plugins import CORE_COMMANDS, PluginRecord, discover, register


class FakeEntryPoint:
    """Stands in for importlib.metadata.EntryPoint.

    Only the surface ossys touches is modelled: name, value, dist, and load().
    """

    def __init__(
        self, name: str, target: Any = None, *, dist: Any = None, raises: Exception | None = None
    ) -> None:
        self.name = name
        self.value = "fake_module:app"
        self.dist = dist
        self._target = target
        self._raises = raises

    def load(self) -> Any:
        if self._raises is not None:
            raise self._raises
        return self._target


class FakeDist:
    def __init__(self, name: str, version: str) -> None:
        self.name = name
        self.version = version


def _app(help_text: str = "fake") -> typer.Typer:
    plugin = typer.Typer(help=help_text)

    @plugin.command()
    def ping() -> None:
        typer.echo("pong")

    return plugin


@pytest.fixture
def entry_points(monkeypatch: pytest.MonkeyPatch) -> list[FakeEntryPoint]:
    """Install a mutable list of fake entry points into discovery."""
    eps: list[FakeEntryPoint] = []
    monkeypatch.setattr("ossys.plugins._entry_points", lambda: eps)
    return eps


# --- happy path ---------------------------------------------------------------------------


def test_no_plugins_installed_is_fine(entry_points: list[FakeEntryPoint]) -> None:
    assert discover(Settings()) == []


def test_plugin_is_discovered_and_mounted(entry_points: list[FakeEntryPoint]) -> None:
    entry_points.append(FakeEntryPoint("docker", _app(), dist=FakeDist("ossys-docker", "1.2.0")))

    app = typer.Typer()
    records = register(app, Settings())

    assert len(records) == 1
    assert records[0].loaded is True
    assert records[0].name == "docker"
    assert records[0].distribution == "ossys-docker 1.2.0"


def test_factory_callable_is_accepted(entry_points: list[FakeEntryPoint]) -> None:
    """A zero-arg callable returning a Typer keeps expensive construction lazy."""
    entry_points.append(FakeEntryPoint("backups", lambda: _app()))
    records = register(typer.Typer(), Settings())
    assert records[0].loaded is True


def test_discovery_is_deterministically_ordered(entry_points: list[FakeEntryPoint]) -> None:
    """Stable output makes `ossys check --json` diffable across a fleet."""
    for name in ("zeta", "alpha", "mid"):
        entry_points.append(FakeEntryPoint(name, _app()))
    records = register(typer.Typer(), Settings())
    assert [r.name for r in records] == ["alpha", "mid", "zeta"]


# --- the kill switch and the allow-list -----------------------------------------------------


def test_disabled_imports_nothing(entry_points: list[FakeEntryPoint]) -> None:
    """enabled = false must not import any third-party module at all."""
    loaded: list[str] = []

    def _explode() -> typer.Typer:
        loaded.append("imported")
        return _app()

    entry_points.append(FakeEntryPoint("docker", _explode))
    assert discover(Settings(plugins_enabled=False)) == []
    assert loaded == []


def test_allowlist_blocks_unlisted_plugins(entry_points: list[FakeEntryPoint]) -> None:
    """On a privileged endpoint this is the difference between 'any installed package can
    add root-run subcommands' and 'these, by name'."""
    entry_points.append(FakeEntryPoint("docker", _app()))
    entry_points.append(FakeEntryPoint("sketchy", _app()))

    records = register(typer.Typer(), Settings(plugins_allowlist=["docker"]))
    by_name = {r.name: r for r in records}

    assert by_name["docker"].loaded is True
    assert by_name["sketchy"].loaded is False
    assert "allowlist" in by_name["sketchy"].error


def test_blocked_plugin_is_never_imported(entry_points: list[FakeEntryPoint]) -> None:
    """The allow-list must gate the *import*, not just the mount — otherwise a rejected
    package still gets to run module-level code as root."""
    imported: list[str] = []

    def _factory() -> typer.Typer:
        imported.append("ran")
        return _app()

    entry_points.append(FakeEntryPoint("sketchy", _factory))

    discover(Settings(plugins_allowlist=["docker"]))
    assert imported == []


def test_empty_allowlist_permits_all(entry_points: list[FakeEntryPoint]) -> None:
    entry_points.append(FakeEntryPoint("anything", _app()))
    assert discover(Settings(plugins_allowlist=[]))[0][0].loaded is True


# --- name rules ------------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(CORE_COMMANDS))
def test_plugin_cannot_shadow_a_core_command(entry_points: list[FakeEntryPoint], name: str) -> None:
    """Otherwise an installed package could silently redefine `useradd` for every timer
    already pointing at it."""
    entry_points.append(FakeEntryPoint(name, _app()))

    app = typer.Typer()
    records = register(app, Settings())

    assert records[0].loaded is False
    assert "shadow" in records[0].error


@pytest.mark.parametrize("name", ["Docker", "1docker", "-docker", "doc ker", "d" * 40, ""])
def test_malformed_names_rejected(entry_points: list[FakeEntryPoint], name: str) -> None:
    entry_points.append(FakeEntryPoint(name, _app()))
    records = register(typer.Typer(), Settings())
    assert records[0].loaded is False
    assert "invalid plugin name" in records[0].error


def test_duplicate_names_are_refused_deterministically(
    entry_points: list[FakeEntryPoint],
) -> None:
    """Picking one silently would make behaviour depend on installation order."""
    entry_points.append(FakeEntryPoint("dupe", _app(), dist=FakeDist("first", "1.0")))
    entry_points.append(FakeEntryPoint("dupe", _app(), dist=FakeDist("second", "2.0")))

    records = register(typer.Typer(), Settings())

    assert records[0].loaded is True
    assert records[1].loaded is False
    assert "duplicate" in records[1].error


# --- failure isolation -------------------------------------------------------------------------


def test_import_error_does_not_break_the_cli(entry_points: list[FakeEntryPoint]) -> None:
    """A broken third-party package must not take down core commands fleet-wide."""
    entry_points.append(FakeEntryPoint("broken", raises=ImportError("no module named nope")))
    entry_points.append(FakeEntryPoint("healthy", _app()))

    records = register(typer.Typer(), Settings())
    by_name = {r.name: r for r in records}

    assert by_name["broken"].loaded is False
    assert "ImportError" in by_name["broken"].error
    assert by_name["healthy"].loaded is True


def test_arbitrary_exception_on_import_is_contained(
    entry_points: list[FakeEntryPoint],
) -> None:
    entry_points.append(FakeEntryPoint("nasty", raises=RuntimeError("module-level boom")))
    records = register(typer.Typer(), Settings())
    assert records[0].loaded is False
    assert "RuntimeError" in records[0].error


def test_wrong_target_type_rejected(entry_points: list[FakeEntryPoint]) -> None:
    entry_points.append(FakeEntryPoint("notatyper", target="just a string"))
    records = register(typer.Typer(), Settings())
    assert records[0].loaded is False
    assert "typer.Typer" in records[0].error


def test_factory_returning_wrong_type_rejected(entry_points: list[FakeEntryPoint]) -> None:
    entry_points.append(FakeEntryPoint("badfactory", target=lambda: 42))
    records = register(typer.Typer(), Settings())
    assert records[0].loaded is False
    assert "factory returned int" in records[0].error


def test_broken_metadata_does_not_crash_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    """A malformed installed distribution must not make ossys unusable."""

    def _boom(**kw: Any) -> Any:
        raise ValueError("corrupt METADATA")

    monkeypatch.setattr("ossys.plugins.metadata.entry_points", _boom)
    assert discover(Settings()) == []


def test_missing_distribution_metadata_is_tolerated(
    entry_points: list[FakeEntryPoint],
) -> None:
    entry_points.append(FakeEntryPoint("orphan", _app(), dist=None))
    records = register(typer.Typer(), Settings())
    assert records[0].loaded is True
    assert records[0].distribution == "unknown"


# --- record shape -------------------------------------------------------------------------------


def test_record_status_maps_to_check_severity() -> None:
    """Loaded is ok; a policy filter is a warning; a real import failure is a failure."""
    assert PluginRecord("a", loaded=True).status == "ok"
    assert (
        PluginRecord("b", loaded=False, error="not in the configured plugins.allowlist").status
        == "warn"
    )
    assert PluginRecord("c", loaded=False, error="ImportError: boom").status == "fail"
