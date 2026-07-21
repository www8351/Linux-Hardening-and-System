"""Module:   ossys.config

Purpose:  Per-endpoint configuration. Lets one ossys build be dropped onto many machines
          and behave differently on each — without changing the command line the timer or
          cron job invokes.

Usage:    from ossys.config import load_settings
          settings = load_settings(path=None, profile=None)   # auto-discovers
          settings = load_settings(profile="workstation")

Discovery order (first hit wins), deliberately different per privilege level:

    1. explicit --config PATH
    2. $OSSYS_CONFIG
    3. ./ossys.toml                      (project-local, dev)
    4. ~/.config/ossys/ossys.toml        (the UNPRIVILEGED path)
    5. /etc/ossys/ossys.toml             (the PRIVILEGED path)

    A root-run system timer lands on /etc/ossys/ossys.toml; a `systemctl --user` timer
    lands on the operator's own ~/.config copy. The same binary, the same argv, two
    policies — which is what makes the two automation paths coexist on one endpoint
    without a wrapper script deciding for them.

Profile selection:
    [defaults] applies everywhere. A [profile.NAME] table overlays it. The active profile is
    chosen by --profile, then $OSSYS_PROFILE, then a hostname match against the profile's
    `hosts` globs, then "default" if such a profile exists. Hostname matching is what makes
    a single config file deployable unchanged across a fleet.

Security notes:
    * `allowed_roots` is the containment list enforced by validate.validate_output_path,
      and is the resolution of DECISIONS.md D-005. The default is deliberately narrow —
      the current working directory only. Widening it is an explicit, auditable edit to a
      file, not an accident of a command line.
    * Config is parsed with tomllib. No exec, no eval, no YAML tags, no pickle: the format
      cannot express code, so a writable config file is a policy problem, not an RCE.
    * A malformed or unreadable config is a hard failure (Exit.CONFIG), never a silent
      fallback to defaults. Silently ignoring a broken policy file on a hardened endpoint
      is how a machine ends up running with controls the operator believes are active.
"""

from __future__ import annotations

import fnmatch
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .exits import ConfigError
from .privilege import DEFAULT_TIMEOUT

# mypy is configured at the declared floor (3.10), where tomllib is not in the stdlib, so
# the first branch is the one that needs the ignore. At runtime on 3.11+ it is the branch
# that succeeds and tomli is never imported.
try:  # Python 3.11+
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # Python 3.10 — the declared floor uses the tomli backport
    import tomli as tomllib

CONFIG_FILENAME = "ossys.toml"


@dataclass
class Settings:
    """Effective configuration after defaults, profile overlay and CLI flags are merged."""

    profile: str = "defaults"
    source: Path | None = None
    """Which file this came from; None means built-in defaults. Reported by `ossys check`."""

    mode: str = "auto"
    """Privilege mode: auto | root | sudo | user. See privilege.detect_mode."""

    allowed_roots: list[str] = field(default_factory=lambda: ["."])
    """Directories output files may be written into (OSSYS-SEC-001 / -002)."""

    timeout: float = DEFAULT_TIMEOUT
    """Seconds before an external command is killed (OSSYS-SEC-006)."""

    json_output: bool = False
    dry_run: bool = False

    require_tools: list[str] = field(default_factory=list)
    """Extra binaries `ossys check` must find on this endpoint."""

    webhook_url: str = ""
    webhook_on_failure: bool = True
    """Optional failure notification. Empty URL disables it entirely."""

    def resolved_roots(self) -> list[Path]:
        """Allowed roots as absolute paths, with ~ and $VARS expanded."""
        from .validate import expand_root

        return [expand_root(r) for r in self.allowed_roots]


def candidate_paths(explicit: str | Path | None = None) -> list[Path]:
    """Return the discovery chain, highest precedence first."""
    paths: list[Path] = []
    if explicit:
        paths.append(Path(explicit).expanduser())
    env = os.environ.get("OSSYS_CONFIG")
    if env:
        paths.append(Path(env).expanduser())
    paths.append(Path.cwd() / CONFIG_FILENAME)
    paths.append(Path.home() / ".config" / "ossys" / CONFIG_FILENAME)
    paths.append(Path("/etc/ossys") / CONFIG_FILENAME)
    return paths


def find_config(explicit: str | Path | None = None) -> Path | None:
    """First existing config in the discovery chain, or None.

    An explicitly requested path that does not exist is an error rather than a fall-through:
    if the operator named a file, running with different settings than they asked for is
    worse than not running.
    """
    if explicit is not None:
        # Resolved directly rather than read back out of the discovery chain: coupling the
        # explicit case to the chain's ordering made this raise IndexError instead of a
        # clean ConfigError whenever the chain was empty or reordered.
        named = Path(explicit).expanduser()
        if not named.is_file():
            raise ConfigError(f"config file not found: {named}")
        return named

    for path in candidate_paths():
        try:
            if path.is_file():
                return path
        except OSError:  # unreadable / permission denied on a chain entry — keep looking
            continue
    return None


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as fh:
            loaded: dict[str, Any] = tomllib.load(fh)
            return loaded
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"malformed TOML in {path}: {exc}") from exc


def _select_profile(data: dict[str, Any], requested: str | None) -> tuple[str, dict[str, Any]]:
    """Pick the active profile table and return ``(name, table)``."""
    profiles: dict[str, Any] = data.get("profile", {}) or {}
    if not isinstance(profiles, dict):
        raise ConfigError("[profile] must be a table of named profiles")

    name = requested or os.environ.get("OSSYS_PROFILE")
    if name:
        if name not in profiles:
            known = ", ".join(sorted(profiles)) or "(none defined)"
            raise ConfigError(f"unknown profile {name!r}; defined profiles: {known}")
        return name, profiles[name]

    # Hostname match — one config file, many endpoints.
    hostname = socket.gethostname()
    for candidate, table in profiles.items():
        patterns = table.get("hosts", []) if isinstance(table, dict) else []
        if any(fnmatch.fnmatch(hostname, str(p)) for p in patterns):
            return candidate, table

    if "default" in profiles:
        return "default", profiles["default"]
    return "defaults", {}


def _coerce(settings: Settings, table: dict[str, Any], source: str) -> None:
    """Overlay one TOML table onto ``settings``, type-checking as it goes."""
    if not isinstance(table, dict):
        raise ConfigError(f"{source} must be a table")

    def _typed(key: str, expected: type, current: Any) -> Any:
        if key not in table:
            return current
        value = table[key]
        if expected is float and isinstance(value, int) and not isinstance(value, bool):
            return float(value)
        if not isinstance(value, expected) or isinstance(value, bool) is not (expected is bool):
            raise ConfigError(f"{source}.{key} must be {expected.__name__}, got {value!r}")
        return value

    settings.mode = _typed("mode", str, settings.mode)
    settings.timeout = _typed("timeout", float, settings.timeout)
    settings.json_output = _typed("json", bool, settings.json_output)
    settings.dry_run = _typed("dry_run", bool, settings.dry_run)

    for key, attr in (("allowed_roots", "allowed_roots"), ("require_tools", "require_tools")):
        if key in table:
            value = table[key]
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise ConfigError(f"{source}.{key} must be a list of strings")
            setattr(settings, attr, value)

    webhook = table.get("webhook")
    if webhook is not None:
        if not isinstance(webhook, dict):
            raise ConfigError(f"{source}.webhook must be a table")
        settings.webhook_url = str(webhook.get("url", settings.webhook_url))
        settings.webhook_on_failure = bool(webhook.get("on_failure", settings.webhook_on_failure))

    if settings.mode not in {"auto", "root", "sudo", "user"}:
        raise ConfigError(
            f"{source}.mode must be one of: auto, root, sudo, user (got {settings.mode!r})"
        )
    if settings.timeout <= 0:
        raise ConfigError(f"{source}.timeout must be positive (got {settings.timeout})")


def load_settings(*, path: str | Path | None = None, profile: str | None = None) -> Settings:
    """Load, merge and validate configuration for this endpoint.

    Built-in defaults → [defaults] table → [profile.NAME] table. Returns fully-populated
    Settings even when no config file exists, so every caller can assume a valid object.
    """
    settings = Settings()
    config_path = find_config(path)
    if config_path is None:
        return settings

    data = _read_toml(config_path)
    settings.source = config_path

    if "defaults" in data:
        _coerce(settings, data["defaults"], "defaults")

    name, table = _select_profile(data, profile)
    if table:
        _coerce(settings, table, f"profile.{name}")
    settings.profile = name

    return settings
