"""Module:   ossys.plugins

Purpose:  Lets new admin domains (Docker management, backups, log rotation) attach as
          isolated packages instead of edits to a growing core file. Phase 4.

Usage:    A plugin package declares an entry point:

              [project.entry-points."ossys.plugins"]
              docker = "ossys_docker:app"

          `app` must be a ``typer.Typer`` instance, or a zero-argument callable returning
          one (useful when construction is expensive and should stay lazy). Core discovers
          it and mounts it as `ossys docker ...`. No edit to ossys is required.

Security notes:
    Entry-point discovery means importing third-party code, and on this tool that import may
    happen in a process running as root. That is inherent to the mechanism — it is how
    pytest, flake8 and every other plugin host works — but it deserves controls that a
    developer tool would not bother with:

    * **The allow-list.** ``[defaults.plugins] allowlist = [...]`` pins exactly which
      plugins a host will load. On a privileged endpoint this is the difference between "any
      package that happens to be installed in the venv can add root-run subcommands" and
      "these three, by name". Empty means allow all, which is the right default for a
      workstation and the wrong one for a fleet — the example config says so.
    * **The kill switch.** ``enabled = false`` disables discovery entirely: no import of any
      third-party module happens at all.
    * **The audit trail.** ``ossys check`` reports every plugin, whether it loaded, and which
      *distribution* it came from. A plugin host with no inventory command is a supply-chain
      blind spot; you cannot review what you cannot enumerate.
    * **Failure isolation.** A plugin that raises on import is recorded and skipped. A broken
      third-party package must never take down `ossys check` or the core commands — that
      would turn a cosmetic dependency problem into a fleet-wide outage.
    * **No shadowing.** A plugin may not claim a core command name. Otherwise an installed
      package could silently redefine `useradd` or `check` and every existing timer would
      quietly start running someone else's code.
    * Names are validated against the same style of anchored allow-list used everywhere else
      in ossys, so a malformed entry-point name cannot produce a strange command surface.

    What this deliberately does NOT do is pretend to sandbox plugins. Once loading is
    permitted the plugin runs with full process privilege; the controls above are about
    *deciding what loads* and *knowing what did*, not about containing it afterwards.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import metadata
from typing import TYPE_CHECKING, Any, Literal

import typer

if TYPE_CHECKING:
    from .config import Settings

ENTRY_POINT_GROUP = "ossys.plugins"

# Mirrors preflight.Status. Declared here rather than imported to keep the dependency
# one-way (preflight imports plugins, never the reverse).
PluginStatus = Literal["ok", "warn", "fail"]

# Rejections that reflect operator policy rather than a broken package. These surface as
# warnings in the checkup: the allow-list doing its job is not a fault.
_POLICY_REJECTIONS = ("not in the", "disabled")

# Command names owned by core. A plugin claiming one of these is refused, not merged.
CORE_COMMANDS = frozenset(
    {"check", "count", "cubes", "details", "archive", "useradd", "version", "plugins"}
)

# Same shape as the username allow-list: anchored end to end, length-bounded, lowercase.
_PLUGIN_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")


@dataclass(frozen=True)
class PluginRecord:
    """One discovered plugin and what happened to it. JSON-serialisable for `ossys check`."""

    name: str
    loaded: bool
    distribution: str = ""
    """Package and version the entry point came from — the audit trail's payload."""

    target: str = ""
    """The entry-point value, e.g. "ossys_docker:app"."""

    error: str = ""
    """Why it did not load. Empty when loaded is True."""

    @property
    def status(self) -> PluginStatus:
        """Severity for the checkup row.

        A plugin filtered out by the allow-list is a warning, not a failure — that is the
        operator's own policy working as configured. A plugin that failed to *import* is a
        failure: something is installed and broken.
        """
        if self.loaded:
            return "ok"
        return "warn" if self.error.startswith(_POLICY_REJECTIONS) else "fail"


def _entry_points() -> list[metadata.EntryPoint]:
    """All entry points in the ossys.plugins group.

    Wrapped so a broken installed distribution — a malformed METADATA file, a stale
    egg-info — cannot crash startup for everyone else.
    """
    try:
        return list(metadata.entry_points(group=ENTRY_POINT_GROUP))
    except Exception:
        return []


def _distribution_of(entry_point: metadata.EntryPoint) -> str:
    """Best-effort "name version" for the distribution providing this entry point."""
    dist = getattr(entry_point, "dist", None)
    if dist is None:
        return "unknown"
    name = getattr(dist, "name", None) or "unknown"
    version = getattr(dist, "version", "") or ""
    return f"{name} {version}".strip()


def _validate_name(name: str) -> str | None:
    """Return an error string if ``name`` is unusable as a subcommand, else None."""
    if not _PLUGIN_NAME_RE.match(name):
        return (
            f"invalid plugin name {name!r} "
            "(lowercase letters, digits and hyphens; must start with a letter; max 32 chars)"
        )
    if name in CORE_COMMANDS:
        return f"refuses to shadow the core command {name!r}"
    return None


def _resolve(loaded: Any) -> typer.Typer:
    """Coerce an entry-point target to a Typer app, accepting a factory callable."""
    if isinstance(loaded, typer.Typer):
        return loaded
    if callable(loaded):
        produced = loaded()
        if isinstance(produced, typer.Typer):
            return produced
        raise TypeError(f"factory returned {type(produced).__name__}, expected typer.Typer")
    raise TypeError(
        f"expected a typer.Typer or a callable returning one, got {type(loaded).__name__}"
    )


def discover(settings: Settings) -> list[tuple[PluginRecord, typer.Typer | None]]:
    """Find, filter and import plugins. Never raises.

    Returns ``(record, app)`` pairs; ``app`` is None for anything that did not load, and the
    record explains why. Ordering is deterministic (by name) so `ossys check` output is
    stable across runs and diffable across a fleet.
    """
    if not settings.plugins_enabled:
        return []

    allowlist = set(settings.plugins_allowlist)
    results: list[tuple[PluginRecord, typer.Typer | None]] = []
    seen: set[str] = set()

    for entry_point in sorted(_entry_points(), key=lambda ep: ep.name):
        name = entry_point.name
        dist = _distribution_of(entry_point)
        target = getattr(entry_point, "value", "")

        def rejected(error: str, _n: str = name, _d: str = dist, _t: str = target) -> PluginRecord:
            return PluginRecord(name=_n, loaded=False, distribution=_d, target=_t, error=error)

        if allowlist and name not in allowlist:
            # Gate the *import*, not just the mount: a rejected package must not get to run
            # module-level code in a possibly-root process.
            results.append((rejected("not in the configured plugins.allowlist"), None))
            continue

        problem = _validate_name(name)
        if problem is not None:
            results.append((rejected(problem), None))
            continue

        if name in seen:
            # Two distributions claiming the same subcommand. Refusing the second is the only
            # deterministic outcome; picking one silently would make behaviour depend on
            # installation order.
            results.append((rejected("duplicate plugin name; first one wins"), None))
            continue

        try:
            plugin_app = _resolve(entry_point.load())
        except Exception as exc:  # one bad plugin must not break the CLI
            results.append((rejected(f"{type(exc).__name__}: {exc}"), None))
            continue

        seen.add(name)
        results.append(
            (PluginRecord(name=name, loaded=True, distribution=dist, target=target), plugin_app)
        )

    return results


def register(app: typer.Typer, settings: Settings) -> list[PluginRecord]:
    """Mount every loadable plugin onto ``app`` and return the full discovery record.

    The record includes plugins that were *rejected*, not just the ones that mounted — an
    operator debugging a missing subcommand needs to see that it was blocked by the
    allow-list rather than absent from the machine.
    """
    records: list[PluginRecord] = []
    for record_, plugin_app in discover(settings):
        records.append(record_)
        if plugin_app is not None:
            app.add_typer(plugin_app, name=record_.name)
    return records
