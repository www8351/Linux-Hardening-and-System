"""Module:   ossys.exits

Purpose:  The exit-code taxonomy and the exception hierarchy that maps onto it. This is the
          contract that makes ossys automatable: a calling script branches on the numeric
          code, never on parsed English text.

Usage:    from ossys.exits import Exit, ValidationError, PermissionDenied
          raise ValidationError("invalid username: 'Bob'")     # → process exits 10

Security notes:
    * Before this module every failure — bad username, missing binary, permission denied —
      escaped as a Python traceback and exit code 1. Callers could not tell "you passed
      garbage" from "the host is misconfigured" from "you are not root", so automation had
      no choice but to treat every non-zero exit as fatal-and-unknown.
    * Tracebacks on stderr also disclosed absolute filesystem paths and module layout into
      CI logs and mailed cron reports. Every ``OssysError`` carries a human-readable message
      instead; the traceback is shown only under ``--debug``.
    * Codes are stable API. Renumbering one silently breaks every wrapper in the field, so
      new failure classes take a new number and never recycle an old one.
"""

from __future__ import annotations

from enum import IntEnum


class Exit(IntEnum):
    """Process exit codes. Stable, documented, machine-branchable.

    Values are spaced by ten so a related sub-case can be slotted in later (e.g. 21 for a
    specific permission failure) without disturbing the existing contract.
    """

    OK = 0
    """Success."""

    VALIDATION = 10
    """Caller supplied bad input — malformed username, out-of-range count, unsafe path."""

    PERMISSION = 20
    """Insufficient privilege: the operation needs root and no elevation route is usable."""

    EXTERNAL = 30
    """An external command failed, timed out, or is not installed."""

    NOOP = 40
    """Nothing to do — the requested state already holds. Success for idempotency purposes.

    Distinct from OK so a scheduler can tell "created the user" from "user already existed"
    without parsing output. Treat as success when branching on failure.
    """

    CONFIG = 50
    """The config file is missing, unreadable, malformed, or names an unknown profile."""

    PREFLIGHT = 60
    """A preflight/checkup assertion failed; the host is not fit to run the operation."""


class OssysError(Exception):
    """Base for every error ossys raises deliberately.

    Carries the exit code with the exception so the CLI boundary needs one handler and no
    isinstance ladder. Anything that is *not* an OssysError escaping to the boundary is a
    bug in ossys, and is reported as such rather than mapped to a tidy code.
    """

    exit_code: Exit = Exit.EXTERNAL

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail


class ValidationError(OssysError):
    """Input failed an allow-list or bounds check. Never reached the system."""

    exit_code = Exit.VALIDATION


class PermissionDenied(OssysError):
    """The operation requires privilege the current process cannot obtain."""

    exit_code = Exit.PERMISSION


class ExternalCommandError(OssysError):
    """An external binary is missing, returned non-zero, or exceeded its timeout."""

    exit_code = Exit.EXTERNAL


class AlreadyDone(OssysError):
    """Idempotency signal: the requested state already holds, so nothing was changed.

    Modelled as an exception because it must short-circuit the operation, but it is a
    *success* outcome — callers branching on failure should treat Exit.NOOP as OK.
    """

    exit_code = Exit.NOOP


class ConfigError(OssysError):
    """The configuration file is missing, malformed, or internally inconsistent."""

    exit_code = Exit.CONFIG


class PreflightError(OssysError):
    """A required host precondition is not met."""

    exit_code = Exit.PREFLIGHT
