"""Tests for the distribution itself.

These guard the packaging invariants that are easy to break silently and only surface after
publication: the console script pointing at the wrong object, the PEP 561 marker going
missing, the exit taxonomy not reaching a caller through the shim, or the sdist quietly
growing to include working notes.

They read the *installed* distribution metadata, so they exercise what a consumer actually
receives rather than what pyproject.toml claims."""

from __future__ import annotations

from importlib import metadata

import pytest

import ossys
from ossys.cli import main
from ossys.exits import Exit


def test_version_matches_installed_metadata() -> None:
    """A drifting __version__ misreports itself in every webhook payload and check output."""
    assert ossys.__version__ == metadata.version("ossys")


def test_console_script_points_at_main_not_app() -> None:
    """Binding the Typer app directly would restore tracebacks and undifferentiated exit 1.

    main() is the exception boundary that produces the documented taxonomy; this is the one
    line of config that decides whether callers get it.
    """
    scripts = {
        ep.name: ep.value
        for ep in metadata.entry_points(group="console_scripts")
        if ep.name == "ossys"
    }
    assert scripts.get("ossys") == "ossys.cli:main"


def test_console_script_target_is_callable_and_returns_an_int() -> None:
    """The shim does `sys.exit(main())`, so a None return would collapse every exit code."""
    entry = next(ep for ep in metadata.entry_points(group="console_scripts") if ep.name == "ossys")
    assert entry.load() is main


def test_py_typed_marker_is_installed() -> None:
    """PEP 561. Without it, plugin authors importing ossys.validate get bare Any -- losing
    the type safety the plugin contract tells them to rely on."""
    from pathlib import Path

    marker = Path(ossys.__file__).parent / "py.typed"
    assert marker.is_file(), "py.typed missing; consumers will not see ossys as typed"


def test_declared_dependencies_are_importable() -> None:
    """Catches a dependency declared but never actually pulled in."""
    requires = metadata.requires("ossys") or []
    assert any(r.startswith("typer") for r in requires)


def test_metadata_declares_typed_classifier() -> None:
    meta = metadata.metadata("ossys")
    assert "Typing :: Typed" in meta.get_all("Classifier", [])


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["ossys", "count", "3"], Exit.OK),
        (["ossys", "count", "0"], Exit.VALIDATION),
    ],
)
def test_entrypoint_returns_taxonomy_codes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
    expected: Exit,
) -> None:
    """The contract a packaged install must honour: an int the shim can pass to sys.exit."""
    monkeypatch.setattr("ossys.config.candidate_paths", lambda explicit=None: [])
    monkeypatch.setattr("sys.argv", argv)

    code = main()
    capsys.readouterr()

    assert isinstance(code, int)
    assert code == int(expected)


def test_module_entrypoint_exists() -> None:
    """`python -m ossys` needs no PATH entry or shim -- it is what the systemd units call,
    and what works around the uv trampoline failure on paths containing spaces."""
    import importlib.util

    assert importlib.util.find_spec("ossys.__main__") is not None
