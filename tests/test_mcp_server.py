"""Tests for ossys.mcp_server — the MCP tool surface.

This is the sharpest edge in the project: it hands tool invocation to a language model, with
arguments the model chose, in response to text that may have come from anywhere. The tests
are therefore mostly about what is *not* reachable.

The tool bodies are plain functions returning plain dicts, so most of this runs without the
optional mcp dependency; the registration tests use it where it is genuinely needed."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from ossys.config import Settings
from ossys.exits import Exit
from ossys.mcp_server import (
    PRIVILEGED_TOOLS,
    READ_ONLY_TOOLS,
    TOOLS_BY_NAME,
    build_server,
    exposed_tools,
    exposure_report,
    tool_archive,
    tool_count,
    tool_details,
    tool_useradd,
    tool_version,
)


def names(**kw: Any) -> list[str]:
    return [spec.name for spec in exposed_tools(Settings(**kw))]


# --- the exposure gate ----------------------------------------------------------------------


def test_default_surface_is_read_only() -> None:
    """Nothing that writes a file or touches the system is exposed out of the box."""
    exposed = names()
    assert set(exposed) == READ_ONLY_TOOLS
    assert all(TOOLS_BY_NAME[n].read_only for n in exposed)


def test_write_tool_requires_explicit_expose() -> None:
    assert "archive" not in names()
    assert "archive" in names(mcp_expose=["archive"])


def test_privileged_tool_needs_two_independent_opt_ins() -> None:
    """Wanting the model to make backups must never silently also mean wanting it to create
    root-capable users."""
    assert "useradd" not in names(mcp_expose=["useradd"])
    assert "useradd" not in names(mcp_allow_privileged=True)
    assert "useradd" in names(mcp_expose=["useradd"], mcp_allow_privileged=True)


def test_allow_privileged_alone_exposes_nothing_extra() -> None:
    assert set(names(mcp_allow_privileged=True)) == READ_ONLY_TOOLS


def test_kill_switch_exposes_nothing() -> None:
    assert names(mcp_enabled=False) == []


def test_exposing_a_write_tool_does_not_leak_the_privileged_one() -> None:
    exposed = names(mcp_expose=["archive", "details"], mcp_allow_privileged=True)
    assert "useradd" not in exposed


def test_unknown_names_in_expose_are_reported_not_silently_ignored() -> None:
    report = exposure_report(Settings(mcp_expose=["archive", "nosuchtool"]))
    assert report["unknown_in_expose"] == ["nosuchtool"]


def test_report_names_tools_blocked_pending_allow_privileged() -> None:
    report = exposure_report(Settings(mcp_expose=["useradd"]))
    assert report["blocked_needs_allow_privileged"] == ["useradd"]
    assert report["privileged_tools"] == []


def test_no_generic_command_runner_exists() -> None:
    """A `run_command` tool would discard every control in ossys.privilege and rebuild the
    os.system hole this project exists to close."""
    forbidden = {"run", "run_command", "exec", "shell", "system", "eval"}
    assert not (forbidden & set(TOOLS_BY_NAME))


# --- honest annotations ------------------------------------------------------------------------


def test_destructive_tools_are_not_marked_read_only() -> None:
    """Clients use readOnlyHint to decide whether to prompt. Mislabelling to dodge a
    confirmation would be actively dishonest."""
    for name in PRIVILEGED_TOOLS | {"archive", "details"}:
        spec = TOOLS_BY_NAME[name]
        assert spec.read_only is False
        assert spec.destructive is True


def test_read_only_tools_are_marked_read_only() -> None:
    for name in READ_ONLY_TOOLS:
        assert TOOLS_BY_NAME[name].read_only is True
        assert TOOLS_BY_NAME[name].destructive is False


# --- tool bodies return envelopes, never raise ----------------------------------------------------


def test_success_envelope_shape() -> None:
    result = tool_version(Settings())
    assert result["ok"] is True
    assert result["exit_code"] == int(Exit.OK)
    assert result["command"] == "version"


def test_validation_error_is_returned_not_raised() -> None:
    """The model should see a taxonomy code, not a traceback disclosing host paths."""
    result = tool_count(Settings(), 0)
    assert result["ok"] is False
    assert result["exit_code"] == int(Exit.VALIDATION)
    assert result["error"] == "validation"
    assert "Traceback" not in result["message"]


def test_path_containment_applies_through_the_mcp_layer(tmp_path: Path) -> None:
    """OSSYS-SEC-001 must hold for a model-supplied path exactly as for a CLI one."""
    settings = Settings(allowed_roots=[str(tmp_path)])
    escaped = str(tmp_path.parent / "escaped.txt")

    result = tool_details(settings, "a", "1", "2", escaped)

    assert result["ok"] is False
    assert result["exit_code"] == int(Exit.VALIDATION)
    assert not Path(escaped).exists()


def test_write_inside_allowed_root_succeeds(tmp_path: Path) -> None:
    settings = Settings(allowed_roots=[str(tmp_path)])
    result = tool_details(settings, "Refael", "30", "555", str(tmp_path / "d.txt"))
    assert result["ok"] is True
    assert (tmp_path / "d.txt").read_text(encoding="utf-8").startswith("Your Name is: Refael")


def test_archive_rejects_a_missing_member(tmp_path: Path) -> None:
    settings = Settings(allowed_roots=[str(tmp_path)])
    result = tool_archive(settings, [str(tmp_path / "nope.txt")], str(tmp_path / "o.tgz"))
    assert result["ok"] is False
    assert result["exit_code"] == int(Exit.VALIDATION)


def test_useradd_refuses_without_an_elevation_route(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ossys.system.sys.platform", "linux")
    result = tool_useradd(Settings(mode="user"), "alice")
    assert result["ok"] is False
    assert result["exit_code"] == int(Exit.PERMISSION)


def test_useradd_rejects_an_injection_style_username() -> None:
    result = tool_useradd(Settings(mode="user"), "bob; rm -rf /")
    assert result["ok"] is False
    assert result["exit_code"] == int(Exit.VALIDATION)


# --- registration ---------------------------------------------------------------------


def _schema_props(tool: Any) -> list[str]:
    return list((tool.inputSchema or {}).get("properties", {}))


def test_settings_is_never_a_model_supplied_argument() -> None:
    """Regression guard for a real defect.

    An earlier _bind used functools.update_wrapper to carry the docstring across. That sets
    __wrapped__, which makes inspect.signature follow through to the *unbound* function and
    re-expose `settings` as a required tool argument -- handing the model the object that
    carries allowed_roots and the privilege mode. Every tool schema must omit it.
    """
    settings = Settings(mcp_expose=["archive", "details", "useradd"], mcp_allow_privileged=True)
    tools = asyncio.run(build_server(settings).list_tools())

    assert tools, "expected tools to be registered"
    for tool in tools:
        assert "settings" not in _schema_props(tool), f"{tool.name} leaks settings"


def test_tool_arguments_survive_binding() -> None:
    """The wrapper must not collapse parameters into *args -- the model would lose every
    argument name and type."""
    tools = {
        t.name: t for t in asyncio.run(build_server(Settings(mcp_expose=["archive"])).list_tools())
    }
    assert _schema_props(tools["ossys_count"]) == ["n"]
    assert set(_schema_props(tools["ossys_archive"])) == {"files", "out"}


def test_unexposed_tools_are_not_registered_at_all() -> None:
    """Gating must remove the tool, not merely refuse it at call time -- an advertised tool
    that always errors still tells the model the capability exists."""
    tools = asyncio.run(build_server(Settings()).list_tools())
    registered = {t.name for t in tools}

    assert "ossys_useradd" not in registered
    assert "ossys_archive" not in registered
    assert "ossys_check" in registered


def test_unexposed_tool_cannot_be_invoked() -> None:
    server = build_server(Settings())
    with pytest.raises(Exception, match=r"[Uu]nknown tool"):
        asyncio.run(server.call_tool("ossys_useradd", {"username": "alice"}))


def test_annotations_reach_the_registered_tool() -> None:
    settings = Settings(mcp_expose=["archive"])
    tools = {t.name: t for t in asyncio.run(build_server(settings).list_tools())}

    check_ann = tools["ossys_check"].annotations
    archive_ann = tools["ossys_archive"].annotations
    assert check_ann is not None and archive_ann is not None, "annotations must reach the client"

    assert check_ann.readOnlyHint is True
    assert archive_ann.readOnlyHint is False
    assert archive_ann.destructiveHint is True


def test_call_through_the_server_returns_the_envelope() -> None:
    async def go() -> Any:
        server = build_server(Settings())
        return await server.call_tool("ossys_count", {"n": 3})

    result = asyncio.run(go())
    payload = result[1] if isinstance(result, tuple) else result
    inner = payload["result"] if isinstance(payload, dict) and "result" in payload else payload
    assert inner["ok"] is True
    assert inner["values"] == [1, 2, 3]
