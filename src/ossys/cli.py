"""Module:   ossys.cli

Purpose:  Non-interactive command-line entrypoint (Typer). Resolves the endpoint's config
          and privilege mode once, then dispatches to validated task/system functions.

Usage:    ossys check --json                       # endpoint checkup (both paths)
          ossys --profile server useradd alice --sudo
          ossys --json --dry-run archive a.log -o backup.tgz
          ossys count 200

Global flags (available on every command):
    --config PATH     explicit config file
    --profile NAME    select a [profile.NAME] table
    --mode MODE       force auto|root|sudo|user, overriding detection
    --json            machine-readable output on stdout
    --dry-run         validate and resolve everything, change nothing
    --timeout SECS    per-external-command timeout
    --debug           show tracebacks instead of clean error messages

Security notes:
    * OSSYS-SEC-009 — previously every failure escaped as a Python traceback with exit code
      1, so a calling script could not distinguish bad input from a misconfigured host, and
      absolute filesystem paths leaked into CI logs and mailed cron reports. `main()` is now
      a single exception boundary mapping each error class onto the documented exit-code
      taxonomy (see ossys.exits), printing a clean message. Tracebacks appear only under
      --debug.
    * An exception that is *not* an OssysError is an ossys bug, and is reported as one
      rather than being laundered into a tidy code that implies the input was at fault.
    * This module remains declarative: it shells out to nothing itself. Every privileged
      action goes through ossys.privilege, every write through ossys.validate.
"""

from __future__ import annotations

import importlib
import random
import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from . import __version__
from .config import Settings, load_settings
from .exits import AlreadyDone, Exit, OssysError
from .notify import WebhookResult, notify_failure
from .output import Emitter
from .plugins import ENTRY_POINT_GROUP, PluginRecord, register
from .preflight import config_search_path, run_checks, summarise
from .privilege import PrivilegeReport, detect_mode
from .system import add_user as _add_user
from .tasks import archive_files, count_to, roll_cubes, save_details

app = typer.Typer(
    help="Small system tasks — safe, non-interactive, automatable.",
    no_args_is_help=True,
)


class Runtime:
    """Per-invocation state resolved once in the callback and carried on the Typer context.

    Privilege detection is deferred (``lazy``) because it runs an external `sudo -n true`
    probe, and the unprivileged commands have no business paying for that — `ossys count 5`
    should not touch sudo at all.
    """

    def __init__(self, settings: Settings, emitter: Emitter, debug: bool) -> None:
        self.settings = settings
        self.out = emitter
        self.debug = debug
        self._privilege: PrivilegeReport | None = None

    @property
    def privilege(self) -> PrivilegeReport:
        if self._privilege is None:
            self._privilege = detect_mode(self.settings.mode)
        return self._privilege


# The active runtime, published so `main()` can reach the resolved Settings from its
# exception handlers. Typer owns the Context, and by the time an exception reaches the
# boundary the Context is gone -- but the webhook needs to know where to POST. Set once by
# the callback; None means config never loaded, in which case no notification is attempted
# (a config we could not parse is not a config we should trust a URL from).
_ACTIVE_RUNTIME: Runtime | None = None

# Discovery results, populated by main() before the command tree is invoked. Kept module
# level for the same reason as _ACTIVE_RUNTIME: registration must happen before Typer parses
# argv, so it cannot live on the Context.
_PLUGIN_RECORDS: list[PluginRecord] = []


def _runtime(ctx: typer.Context) -> Runtime:
    obj = ctx.obj
    if not isinstance(
        obj, Runtime
    ):  # pragma: no cover - only reachable if the callback is bypassed
        raise RuntimeError("runtime not initialised; the Typer callback did not run")
    return obj


@app.callback()
def main_callback(
    ctx: typer.Context,
    config: Annotated[
        Path | None, typer.Option("--config", help="Explicit config file path")
    ] = None,
    profile: Annotated[
        str | None, typer.Option("--profile", help="Config profile to activate")
    ] = None,
    mode: Annotated[
        str | None, typer.Option("--mode", help="Force privilege mode: auto|root|sudo|user")
    ] = None,
    json_out: Annotated[
        bool, typer.Option("--json", help="Machine-readable output on stdout")
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Validate and resolve, but change nothing")
    ] = False,
    timeout: Annotated[
        float | None, typer.Option("--timeout", help="Per-command timeout in seconds")
    ] = None,
    debug: Annotated[bool, typer.Option("--debug", help="Show tracebacks on error")] = False,
) -> None:
    """Resolve configuration and build the runtime shared by every subcommand."""
    settings = load_settings(path=config, profile=profile)

    # CLI flags win over config, which wins over built-in defaults. --json and --dry-run are
    # one-way switches: a config that enables them cannot be turned off by omitting the flag,
    # which is the correct precedence for a safety flag like --dry-run.
    if mode is not None:
        settings.mode = mode
    if timeout is not None:
        settings.timeout = timeout
    settings.json_output = settings.json_output or json_out
    settings.dry_run = settings.dry_run or dry_run

    global _ACTIVE_RUNTIME
    ctx.obj = _ACTIVE_RUNTIME = Runtime(
        settings=settings,
        emitter=Emitter(json_mode=settings.json_output, dry_run=settings.dry_run),
        debug=debug,
    )


@app.command()
def check(
    ctx: typer.Context,
    strict: Annotated[
        bool, typer.Option("--strict", help="Treat warnings as failures (deployment gate)")
    ] = False,
) -> None:
    """Run the endpoint checkup: privilege path, tools, config, output roots.

    Read-only and safe to schedule on every endpoint. Exits 0 when the host is fit to run,
    60 (Exit.PREFLIGHT) when it is not.
    """
    rt = _runtime(ctx)
    settings = rt.settings
    checks = run_checks(settings, _PLUGIN_RECORDS)
    verdict = summarise(checks, strict=strict)

    payload: dict[str, Any] = {
        **verdict,
        "version": __version__,
        "profile": settings.profile,
        "config": str(settings.source) if settings.source else None,
        "config_search_path": config_search_path(),
        "mode_requested": settings.mode,
        "allowed_roots": [str(p) for p in settings.resolved_roots()],
        "timeout": settings.timeout,
        "dry_run": settings.dry_run,
        "plugins": [
            {"name": r.name, "loaded": r.loaded, "distribution": r.distribution}
            for r in _PLUGIN_RECORDS
        ],
    }

    if settings.json_output:
        rt.out.raw_json(payload)
    else:
        symbols = {"ok": "PASS", "warn": "WARN", "fail": "FAIL"}
        width = max(len(c.name) for c in checks)
        for c in checks:
            typer.echo(f"[{symbols[c.status]}] {c.name.ljust(width)}  {c.detail}")
        counts = verdict["counts"]
        typer.echo(f"\n{counts['ok']} passed, {counts['warn']} warnings, {counts['fail']} failures")

    raise typer.Exit(int(Exit.OK if verdict["ok"] else Exit.PREFLIGHT))


@app.command()
def count(ctx: typer.Context, n: Annotated[int, typer.Argument(help="Count from 1 to N")]) -> None:
    """Print 1..N, one per line."""
    rt = _runtime(ctx)
    values = list(count_to(n))
    rt.out.result("count", {"n": n, "values": values}, lines=[str(v) for v in values])


@app.command()
def cubes(
    ctx: typer.Context,
    rounds: Annotated[int, typer.Argument(help="How many rounds to roll")],
    seed: Annotated[int | None, typer.Option("--seed", help="Seed for reproducible rolls")] = None,
    sides: Annotated[int, typer.Option("--sides", help="Faces per cube")] = 10,
) -> None:
    """Roll two cubes each round and report matches."""
    rt = _runtime(ctx)
    rng = random.Random(seed) if seed is not None else None
    rolls = roll_cubes(rounds, sides=sides, rng=rng)
    rt.out.result(
        "cubes",
        {
            "rounds": rounds,
            "sides": sides,
            "seed": seed,
            "matches": sum(1 for r in rolls if r.is_match),
            "rolls": [{"cube1": r.cube1, "cube2": r.cube2, "match": r.is_match} for r in rolls],
        },
        lines=[f"{r.cube1} vs {r.cube2} — {'match!' if r.is_match else 'no match'}" for r in rolls],
    )


@app.command()
def details(
    ctx: typer.Context,
    name: Annotated[str, typer.Option("--name")],
    age: Annotated[str, typer.Option("--age")],
    phone: Annotated[str, typer.Option("--phone")],
    out: Annotated[Path, typer.Option("--out", "-o")] = Path("details.txt"),
) -> None:
    """Write contact details to a file inside an allowed output root."""
    rt = _runtime(ctx)
    roots = rt.settings.resolved_roots()

    if rt.settings.dry_run:
        from .validate import validate_output_path

        target = validate_output_path(out, allowed_roots=roots)
        rt.out.result(
            "details",
            {"path": str(target), "written": False},
            lines=[f"Would write {target}"],
        )
        return

    path = save_details(name, age, phone, out, allowed_roots=roots)
    rt.out.result("details", {"path": str(path), "written": True}, lines=[f"Wrote {path}"])


@app.command()
def archive(
    ctx: typer.Context,
    files: Annotated[list[Path], typer.Argument(help="Files to archive")],
    out: Annotated[Path, typer.Option("--out", "-o")] = Path("archive.tgz"),
) -> None:
    """Create a .tgz archive of the given files."""
    rt = _runtime(ctx)
    roots = rt.settings.resolved_roots()

    if rt.settings.dry_run:
        from .validate import validate_archive_members, validate_output_path

        members = validate_archive_members(list(files))
        target = validate_output_path(out, allowed_roots=roots)
        rt.out.result(
            "archive",
            {"path": str(target), "members": [m.name for m in members], "created": False},
            lines=[f"Would create {target} with {len(members)} member(s)"],
        )
        return

    path = archive_files(list(files), out, allowed_roots=roots)
    rt.out.result(
        "archive",
        {"path": str(path), "members": [Path(f).name for f in files], "created": True},
        lines=[f"Created {path}"],
    )


@app.command()
def useradd(
    ctx: typer.Context,
    username: Annotated[str, typer.Argument(help="Username to create (Linux)")],
    sudo: Annotated[bool, typer.Option("--sudo", help="Add to the sudo group")] = False,
) -> None:
    """Create a system user (Linux only). Idempotent — exits 40 if the user exists.

    Requires an elevation route: run as root, or with passwordless sudo configured. Check
    which path this endpoint has with `ossys check`.
    """
    rt = _runtime(ctx)
    result = _add_user(
        username,
        mode=rt.privilege.mode,
        sudo_group=sudo,
        timeout=rt.settings.timeout,
        dry_run=rt.settings.dry_run,
    )
    verb = "Would create" if result.dry_run else "Created"
    rt.out.result(
        "useradd",
        {
            "username": result.username,
            "created": result.created,
            "sudo_group": result.sudo_group,
            "privilege_mode": rt.privilege.mode.value,
        },
        lines=[f"{verb} user {result.username}"],
    )


@app.command()
def plugins(ctx: typer.Context) -> None:
    """List discovered plugins, whether they loaded, and which package they came from.

    A plugin host without an inventory command is a supply-chain blind spot: entry points
    add subcommands that may run as root, and you cannot review what you cannot enumerate.
    Rejected plugins are listed too, so a missing subcommand is distinguishable from one
    blocked by the allow-list.
    """
    rt = _runtime(ctx)
    records = _PLUGIN_RECORDS

    rt.out.result(
        "plugins",
        {
            "group": ENTRY_POINT_GROUP,
            "enabled": rt.settings.plugins_enabled,
            "allowlist": rt.settings.plugins_allowlist,
            "count": sum(1 for r in records if r.loaded),
            "plugins": [
                {
                    "name": r.name,
                    "loaded": r.loaded,
                    "distribution": r.distribution,
                    "target": r.target,
                    "error": r.error,
                }
                for r in records
            ],
        },
        lines=(
            [
                f"[{'OK ' if r.loaded else 'SKIP'}] {r.name:<16} "
                f"{r.distribution or '-':<28} {r.error}".rstrip()
                for r in records
            ]
            or ["no plugins installed"]
        ),
    )


@app.command()
def version(ctx: typer.Context) -> None:
    """Print the ossys version."""
    rt = _runtime(ctx)
    rt.out.result("version", {"version": __version__}, lines=[__version__])


def _usage_error_type() -> type[BaseException] | None:
    """Resolve the underlying Click ``ClickException`` class, wherever it currently lives.

    Typer 0.26 dropped its public dependency on ``click`` and vendored it as
    ``typer._click``; older versions used the real ``click`` package. Importing either name
    unconditionally breaks on the other, so both are probed and a miss is tolerated —
    usage errors then fall through to the generic handler rather than crashing the
    entrypoint. Only ``typer.Exit`` and ``typer.Abort`` are stable public API, and those are
    caught by name above.
    """
    for module_name in ("typer._click.exceptions", "click.exceptions"):
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError:
            continue
        cls = getattr(module, "ClickException", None)
        if isinstance(cls, type) and issubclass(cls, BaseException):
            return cls
    return None


def _notify(command: str, code: Exit, message: str, detail: str | None = None) -> WebhookResult:
    """Fire the optional failure webhook. Never raises, never alters the exit code.

    Reads Settings off the module-level runtime because the Typer Context is already unwound
    by the time an exception reaches the boundary. If the callback never ran — a config error,
    a usage error — there are no trustworthy settings and no notification is sent.
    """
    if _ACTIVE_RUNTIME is None:
        return WebhookResult.skipped("settings unavailable (config did not load)")
    settings = _ACTIVE_RUNTIME.settings
    return notify_failure(
        settings,
        command=command,
        exit_code=int(code),
        message=message,
        detail=detail,
        dry_run=settings.dry_run,
    )


def _fail(
    emitter: Emitter, command: str, code: Exit, message: str, detail: str | None = None
) -> int:
    """Report a failure and notify, in that order. Returns the exit code unchanged.

    Ordering matters: the local report is emitted first so a slow or dead collector cannot
    delay or suppress the operator-visible output.
    """
    emitter.failure(command, code, message, detail)
    result = _notify(command, code, message, detail)
    if result.attempted and not result.delivered:
        # Surfaced on stderr, never fatal — a broken alerting path must not turn a
        # validation error into something else.
        emitter.note(f"warning: failure notification not delivered ({result.reason})")
    return int(code)


def _preparse(argv: list[str], flag: str) -> str | None:
    """Pull a single ``--flag value`` (or ``--flag=value``) out of argv without full parsing.

    Plugin registration has to happen *before* Typer parses argv — a subcommand that is not
    on the app yet cannot be dispatched to — but the allow-list that governs registration
    lives in the config file, which is selected by ``--config`` / ``--profile``. This walks
    argv for just those two options. It is deliberately not a parser: anything it gets wrong
    is corrected moments later when the callback does the real load.
    """
    for i, arg in enumerate(argv):
        if arg == flag and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith(f"{flag}="):
            return arg.split("=", 1)[1]
    return None


def _register_plugins() -> list[PluginRecord]:
    """Mount plugins before the command tree is parsed. Never raises.

    Settings are loaded a second time here (the callback does the authoritative load). If
    that fails — malformed TOML, unknown profile — discovery is skipped entirely rather than
    falling back to permissive defaults: a config we cannot parse is not a config whose
    allow-list we should guess at. The real ConfigError surfaces from the callback with a
    proper exit code.
    """
    try:
        settings = load_settings(
            path=_preparse(sys.argv, "--config"), profile=_preparse(sys.argv, "--profile")
        )
    except Exception:
        return []
    return register(app, settings)


def main() -> int:
    """Console-script entrypoint. The single exception boundary (OSSYS-SEC-009).

    Maps every deliberate error onto the documented exit-code taxonomy so callers branch on
    a number, never on parsed text, and fires the optional failure webhook on the way out.
    """
    debug = "--debug" in sys.argv
    json_mode = "--json" in sys.argv
    emitter = Emitter(json_mode=json_mode)
    command = next((a for a in sys.argv[1:] if not a.startswith("-")), "ossys")
    usage_error = _usage_error_type()

    global _PLUGIN_RECORDS
    _PLUGIN_RECORDS = _register_plugins()

    try:
        # With standalone_mode=False, Typer/Click does NOT re-raise `typer.Exit` — it catches
        # it and *returns* the code (see typer/core.py `_main`). Discarding this return value
        # silently collapsed every deliberate exit, including `check --strict` failures, to 0.
        # ClickException and Abort *are* re-raised, and are handled below.
        rv = app(standalone_mode=False)
    except AlreadyDone as exc:
        # Idempotency is a *success* outcome with its own code, so schedulers can tell
        # "created" from "already there" without treating the latter as a failure.
        emitter.result(command, {"noop": True, "message": exc.message}, lines=[exc.message])
        return int(Exit.NOOP)
    except OssysError as exc:
        if debug:
            raise
        return _fail(emitter, command, exc.exit_code, exc.message, exc.detail)
    except typer.Exit as exc:  # pragma: no cover - only if a future Typer re-raises instead
        return int(exc.exit_code)
    except typer.Abort:
        emitter.failure(command, Exit.EXTERNAL, "aborted")
        return 130
    except KeyboardInterrupt:
        emitter.failure(command, Exit.EXTERNAL, "interrupted")
        return 130
    except Exception as exc:  # boundary of last resort
        if usage_error is not None and isinstance(exc, usage_error):
            # Usage errors (unknown flag, missing argument). Click owns the message and the
            # conventional exit code 2; do not remap it into the ossys taxonomy, which
            # describes operational outcomes rather than "you typed it wrong".
            show = getattr(exc, "show", None)
            if callable(show):
                show()
            return int(getattr(exc, "exit_code", 2))
        if debug:
            raise
        # Not an OssysError => a bug in ossys, not bad input. Say so plainly rather than
        # laundering it into a taxonomy code that blames the caller.
        return _fail(
            emitter,
            command,
            Exit.EXTERNAL,
            f"internal error: {type(exc).__name__}: {exc}",
            "This is a bug in ossys; re-run with --debug for a traceback.",
        )

    # A command that returned an int did so via `typer.Exit`; anything else is a normal
    # successful return. A non-zero code here is a deliberate exit (today: `check` failing
    # its preflight), which still warrants a notification -- it is exactly the case a fleet
    # operator wants to hear about.
    code = rv if isinstance(rv, int) else int(Exit.OK)
    if code not in (int(Exit.OK), int(Exit.NOOP)):
        _notify(command, Exit(code), f"{command} exited {code}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
