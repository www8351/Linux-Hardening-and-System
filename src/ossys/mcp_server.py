"""Module:   ossys.mcp_server

Purpose:  Exposes ossys operations as MCP tools, so Claude Code / Claude Desktop can call
          them directly instead of shelling out and parsing text. Phase 6 (stretch).

Install:  pip install "ossys[mcp]"

Usage:    ossys-mcp                     # stdio transport, the usual MCP wiring
          python -m ossys.mcp_server

          Claude Desktop / Claude Code config:

              {"mcpServers": {"ossys": {"command": "ossys-mcp"}}}

Security notes:
    This is the most dangerous surface in the project, and it is built accordingly. An MCP
    server hands tool invocation to a language model: whatever is exposed can be called on
    the model's initiative, with arguments the model chose, in response to text that may
    have come from anywhere. On a tool that can create system accounts as root, "the model
    decides" is not an acceptable trust boundary on its own.

    So the defaults are closed and widening them is a deliberate, auditable act:

    * **Read-only by default.** Only `check`, `plugins`, `version`, `count` and `cubes` are
      registered out of the box. Nothing that writes a file or touches the system is exposed
      unless a config file names it in ``[defaults.mcp] expose``.
    * **Privileged operations need a second, separate switch.** ``useradd`` requires
      ``allow_privileged = true`` *in addition to* being listed in ``expose``. Two
      independent opt-ins, because "I wanted the model to be able to make backups" should
      never silently also mean "I wanted the model to be able to create root-capable users".
    * **Config only — no CLI flag, no environment variable.** Widening the surface requires
      editing a file that lives on the endpoint and can be reviewed, version-controlled and
      diffed. A flag could be added by whatever launched the server; a file is policy.
    * **Never a generic command runner.** There is deliberately no `run_command` tool. That
      single convenience would discard every control in `ossys.privilege` — the argv lists,
      the resolved absolute paths, the timeouts, the minimal environment — and turn this back
      into the `os.system` hole the whole project exists to close.
    * **Every tool goes through the same validators as the CLI.** Paths are contained by
      ``validate_output_path``, usernames by ``validate_username``, external commands by
      ``ossys.privilege.run``. The model gets no path around them.
    * **Errors are returned, not raised.** A failing tool answers with the same structured
      envelope the CLI emits under ``--json``, carrying the exit-code taxonomy. The model
      sees "exit 20, no elevation route", not a traceback disclosing host paths.
    * **Tool annotations are set honestly.** ``readOnlyHint`` and ``destructiveHint`` let a
      client warn or prompt before a call. Marking a destructive tool read-only to avoid a
      confirmation prompt would be actively dishonest, so the annotations are derived from
      the same table that decides exposure.

    Residual risk that this design does NOT eliminate: if an operator exposes `useradd` and
    runs the server as root, a prompt-injected model can create accounts. No amount of
    in-process validation fixes that — it is a deployment decision. `ossys check` and the
    startup banner both report exactly which tools are live so the decision stays visible.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from . import __version__
from .config import Settings, load_settings
from .exits import Exit, OssysError
from .plugins import register as register_plugins
from .preflight import run_checks, summarise
from .privilege import detect_mode
from .system import add_user as _add_user
from .tasks import archive_files, count_to, roll_cubes, save_details

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps mcp an optional dependency
    from mcp.server.fastmcp import FastMCP

# Tools registered unconditionally. Every one of these is read-only: it inspects the host or
# computes a value, and changes nothing.
READ_ONLY_TOOLS = frozenset({"check", "plugins", "version", "count", "cubes"})

# Tools that require an explicit `expose` entry. Splitting "writes a file" from "mutates the
# system" matters: an operator may reasonably want the first and not the second.
WRITE_TOOLS = frozenset({"archive", "details"})
PRIVILEGED_TOOLS = frozenset({"useradd"})


@dataclass(frozen=True)
class ToolSpec:
    """One exposable tool and the truth about what it does.

    ``read_only`` and ``destructive`` feed the MCP annotations a client uses to decide
    whether to warn the user, so they must describe the tool honestly rather than
    conveniently.
    """

    name: str
    handler: Callable[..., dict[str, Any]]
    description: str
    read_only: bool
    destructive: bool = False
    idempotent: bool = False
    requires_privilege: bool = False


def _ok(command: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Success envelope — the same shape the CLI emits under --json."""
    return {"ok": True, "command": command, "exit_code": int(Exit.OK), **payload}


def _err(command: str, exc: OssysError) -> dict[str, Any]:
    """Failure envelope. Returned, never raised, so the model gets structure not a trace."""
    envelope: dict[str, Any] = {
        "ok": False,
        "command": command,
        "exit_code": int(exc.exit_code),
        "error": exc.exit_code.name.lower(),
        "message": exc.message,
    }
    if exc.detail:
        envelope["detail"] = exc.detail
    return envelope


def _guard(command: str, fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """Run a tool body, converting any deliberate ossys error into a structured envelope.

    Anything that is not an OssysError is a bug in ossys and is reported as one, exactly as
    the CLI boundary does — not laundered into a code that blames the caller's arguments.
    """
    try:
        return _ok(command, fn())
    except OssysError as exc:
        return _err(command, exc)
    except Exception as exc:  # boundary of last resort
        return {
            "ok": False,
            "command": command,
            "exit_code": int(Exit.EXTERNAL),
            "error": "internal",
            "message": f"internal error: {type(exc).__name__}: {exc}",
        }


# --- tool bodies ------------------------------------------------------------------------
# Plain functions returning plain dicts. Kept free of any MCP types so they are directly
# testable without the optional dependency installed, and so the registration layer stays a
# thin adapter rather than the place logic hides.


def tool_version(settings: Settings) -> dict[str, Any]:
    return _guard("version", lambda: {"version": __version__})


def tool_check(settings: Settings, strict: bool = False) -> dict[str, Any]:
    def body() -> dict[str, Any]:
        checks = run_checks(settings)
        verdict = summarise(checks, strict=strict)
        return {
            **verdict,
            "profile": settings.profile,
            "config": str(settings.source) if settings.source else None,
        }

    return _guard("check", body)


def tool_plugins(settings: Settings) -> dict[str, Any]:
    def body() -> dict[str, Any]:
        import typer

        records = register_plugins(typer.Typer(), settings)
        return {
            "count": sum(1 for r in records if r.loaded),
            "plugins": [
                {
                    "name": r.name,
                    "loaded": r.loaded,
                    "distribution": r.distribution,
                    "error": r.error,
                }
                for r in records
            ],
        }

    return _guard("plugins", body)


def tool_count(settings: Settings, n: int) -> dict[str, Any]:
    return _guard("count", lambda: {"n": n, "values": list(count_to(n))})


def tool_cubes(
    settings: Settings, rounds: int, sides: int = 10, seed: int | None = None
) -> dict[str, Any]:
    def body() -> dict[str, Any]:
        rng = random.Random(seed) if seed is not None else None  # noqa: S311 - demo output
        rolls = roll_cubes(rounds, sides=sides, rng=rng)
        return {
            "rounds": rounds,
            "sides": sides,
            "seed": seed,
            "matches": sum(1 for r in rolls if r.is_match),
            "rolls": [{"cube1": r.cube1, "cube2": r.cube2, "match": r.is_match} for r in rolls],
        }

    return _guard("cubes", body)


def tool_archive(settings: Settings, files: list[str], out: str) -> dict[str, Any]:
    def body() -> dict[str, Any]:
        path = archive_files(list(files), out, allowed_roots=settings.resolved_roots())
        return {"path": str(path), "members": len(files), "created": True}

    return _guard("archive", body)


def tool_details(settings: Settings, name: str, age: str, phone: str, out: str) -> dict[str, Any]:
    def body() -> dict[str, Any]:
        path = save_details(name, age, phone, out, allowed_roots=settings.resolved_roots())
        return {"path": str(path), "written": True}

    return _guard("details", body)


def tool_useradd(settings: Settings, username: str, sudo_group: bool = False) -> dict[str, Any]:
    def body() -> dict[str, Any]:
        result = _add_user(
            username,
            mode=detect_mode(settings.mode).mode,
            sudo_group=sudo_group,
            timeout=settings.timeout,
            dry_run=settings.dry_run,
        )
        return {
            "username": result.username,
            "created": result.created,
            "sudo_group": result.sudo_group,
            "dry_run": result.dry_run,
        }

    return _guard("useradd", body)


# --- the exposure table -------------------------------------------------------------------

_ALL_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "version",
        tool_version,
        "Report the installed ossys version.",
        read_only=True,
        idempotent=True,
    ),
    ToolSpec(
        "check",
        tool_check,
        "Run the read-only endpoint checkup: privilege path, required tools, config "
        "discovery, output roots, webhook posture and loaded plugins.",
        read_only=True,
        idempotent=True,
    ),
    ToolSpec(
        "plugins",
        tool_plugins,
        "List discovered ossys plugins, whether each loaded, and the distribution it came from.",
        read_only=True,
        idempotent=True,
    ),
    ToolSpec(
        "count",
        tool_count,
        "Return the integers 1..n. Pure computation; touches nothing.",
        read_only=True,
        idempotent=True,
    ),
    ToolSpec(
        "cubes",
        tool_cubes,
        "Roll two dice for the given number of rounds. Pure computation; not a source of "
        "security-grade randomness.",
        read_only=True,
    ),
    ToolSpec(
        "archive",
        tool_archive,
        "Create a .tgz archive of the given files. Writes to disk, contained within the "
        "endpoint's configured allowed_roots.",
        read_only=False,
        destructive=True,
    ),
    ToolSpec(
        "details",
        tool_details,
        "Write contact details to a file, contained within the endpoint's configured "
        "allowed_roots.",
        read_only=False,
        destructive=True,
    ),
    ToolSpec(
        "useradd",
        tool_useradd,
        "Create a Linux system user, optionally adding it to the sudo group. PRIVILEGED and "
        "state-changing. Idempotent: a user that already exists is a no-op.",
        read_only=False,
        destructive=True,
        idempotent=True,
        requires_privilege=True,
    ),
)

TOOLS_BY_NAME: dict[str, ToolSpec] = {spec.name: spec for spec in _ALL_TOOLS}


def exposed_tools(settings: Settings) -> list[ToolSpec]:
    """Decide which tools this endpoint registers. Closed by default.

    Read-only tools are always available. Everything else must be named in
    ``[defaults.mcp] expose``, and privileged tools additionally require
    ``allow_privileged = true`` — two independent opt-ins, so widening the surface for a
    harmless reason cannot silently widen it for a dangerous one.
    """
    if not settings.mcp_enabled:
        return []

    requested = set(settings.mcp_expose)
    selected: list[ToolSpec] = []

    for spec in _ALL_TOOLS:
        if spec.name in READ_ONLY_TOOLS:
            selected.append(spec)
            continue
        if spec.name not in requested:
            continue
        if spec.requires_privilege and not settings.mcp_allow_privileged:
            continue
        selected.append(spec)

    return selected


def exposure_report(settings: Settings) -> dict[str, Any]:
    """Summarise the live tool surface. Reported at startup and by `ossys check`.

    An MCP server whose surface cannot be enumerated is one nobody can review. This is the
    same argument as the plugin inventory, applied to a sharper edge.
    """
    live = exposed_tools(settings)
    unknown = sorted(set(settings.mcp_expose) - set(TOOLS_BY_NAME))
    blocked = sorted(
        name
        for name in settings.mcp_expose
        if name in TOOLS_BY_NAME
        and TOOLS_BY_NAME[name].requires_privilege
        and not settings.mcp_allow_privileged
    )
    return {
        "enabled": settings.mcp_enabled,
        "tools": [s.name for s in live],
        "writable_tools": [s.name for s in live if not s.read_only],
        "privileged_tools": [s.name for s in live if s.requires_privilege],
        "blocked_needs_allow_privileged": blocked,
        "unknown_in_expose": unknown,
        "allow_privileged": settings.mcp_allow_privileged,
        "dry_run": settings.dry_run,
    }


# --- server construction --------------------------------------------------------------------


def build_server(settings: Settings) -> FastMCP:
    """Build a FastMCP server exposing exactly the tools this endpoint permits.

    The mcp SDK is imported here rather than at module scope so that ossys stays installable
    and testable without the optional dependency — the tool bodies above are the interesting
    part and they have no MCP types in them at all.
    """
    try:
        from mcp.server.fastmcp import FastMCP as _FastMCP
        from mcp.types import ToolAnnotations
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised by a dedicated test
        raise OssysError(
            "the MCP server requires the optional 'mcp' dependency; "
            'install it with: pip install "ossys[mcp]"'
        ) from exc

    server = _FastMCP("ossys")

    for spec in exposed_tools(settings):
        annotations = ToolAnnotations(
            title=f"ossys {spec.name}",
            readOnlyHint=spec.read_only,
            destructiveHint=spec.destructive,
            idempotentHint=spec.idempotent,
            openWorldHint=False,
        )
        server.add_tool(
            _bind(spec, settings),
            name=f"ossys_{spec.name}",
            description=spec.description,
            annotations=annotations,
        )

    return server


def _bind(spec: ToolSpec, settings: Settings) -> Callable[..., dict[str, Any]]:
    """Bind settings into a tool handler, hiding it from the generated tool schema.

    FastMCP derives each tool's JSON schema from the handler's signature, so the wrapper must
    keep the real parameters introspectable — collapsing them into ``*args`` would leave the
    model with no argument names or types.

    It must equally *not* expose ``settings``. That parameter carries the endpoint's policy,
    including ``allowed_roots``, and it belongs to the operator, not to the model. An earlier
    version of this function called ``functools.update_wrapper`` to carry the docstring
    across; that sets ``__wrapped__``, which makes ``inspect.signature`` follow through to the
    *unbound* function and re-expose ``settings`` as a required tool argument. The fix is to
    compute the trimmed signature explicitly and never set ``__wrapped__``.
    """
    import functools
    import inspect

    bound = functools.partial(spec.handler, settings)

    original = inspect.signature(spec.handler)
    trimmed = original.replace(
        parameters=[p for name, p in original.parameters.items() if name != "settings"]
    )
    # Assigned on the partial object, which FastMCP introspects directly. No __wrapped__.
    bound.__signature__ = trimmed  # type: ignore[attr-defined]
    bound.__name__ = f"ossys_{spec.name}"  # type: ignore[attr-defined]
    bound.__doc__ = spec.description

    return bound


def main() -> int:
    """Console-script entrypoint for `ossys-mcp`.

    Prints the live tool surface to stderr before serving. stdout is the MCP transport and
    must carry nothing but protocol traffic — the same stdout discipline as `--json`.
    """
    import sys

    try:
        settings = load_settings()
    except OssysError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        return int(exc.exit_code)

    report = exposure_report(settings)
    print(f"ossys-mcp {__version__}: exposing {len(report['tools'])} tool(s)", file=sys.stderr)
    print(f"  read-only : {[t for t in report['tools'] if t in READ_ONLY_TOOLS]}", file=sys.stderr)
    if report["writable_tools"]:
        print(f"  WRITABLE  : {report['writable_tools']}", file=sys.stderr)
    if report["privileged_tools"]:
        print(f"  PRIVILEGED: {report['privileged_tools']}", file=sys.stderr)
    if report["unknown_in_expose"]:
        print(
            f"  warning: unknown names in mcp.expose: {report['unknown_in_expose']}",
            file=sys.stderr,
        )
    if report["blocked_needs_allow_privileged"]:
        print(
            f"  note: blocked pending allow_privileged: {report['blocked_needs_allow_privileged']}",
            file=sys.stderr,
        )

    try:
        build_server(settings).run(transport="stdio")
    except OssysError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        return int(exc.exit_code)
    return int(Exit.OK)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
