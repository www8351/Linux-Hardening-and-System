"""Module:   ossys.output

Purpose:  Every byte ossys prints goes through here, so `--json` is a global guarantee
          rather than a per-command afterthought.

Usage:    from ossys.output import Emitter
          out = Emitter(json_mode=True)
          out.result("useradd", {"username": "alice", "created": True})

Security notes:
    * Machine-readable output is what lets a caller branch on structure instead of parsing
      English. Combined with the exits taxonomy it is the whole automation contract.
    * Human text and diagnostics go to **stderr**; only the payload goes to stdout. A caller
      doing `ossys archive ... --json | jq` must never receive a progress line glued to its
      data — the same defect OSSYS-SEC-015 flagged in scripts/menu.sh.
    * Errors are emitted as JSON too when --json is active. An automated caller hitting a
      failure path should not suddenly have to parse prose.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import typer

from .exits import Exit


class Emitter:
    """Renders results as either human text or a single JSON document.

    One instance is built at the CLI boundary and carried on the runtime, so no command
    decides for itself how to print.
    """

    def __init__(self, *, json_mode: bool = False, dry_run: bool = False) -> None:
        self.json_mode = json_mode
        self.dry_run = dry_run

    def note(self, message: str) -> None:
        """Diagnostic for humans. Always stderr — never pollutes a parsed stdout."""
        if not self.json_mode:
            typer.echo(message, err=True)

    def line(self, text: str) -> None:
        """A line of ordinary human output. Suppressed entirely in JSON mode."""
        if not self.json_mode:
            typer.echo(text)

    def result(
        self, command: str, payload: dict[str, Any], *, lines: list[str] | None = None
    ) -> None:
        """Emit a successful result.

        Args:
            command: The subcommand name, echoed into the JSON envelope so a log aggregator
                     can tell records apart without external context.
            payload: The structured result.
            lines:   Human-readable rendering, used only when JSON is off.
        """
        if self.json_mode:
            envelope = {
                "ok": True,
                "command": command,
                "exit_code": int(Exit.OK),
                "dry_run": self.dry_run,
                **payload,
            }
            typer.echo(json.dumps(envelope, indent=2, default=str))
            return
        for line in lines or []:
            typer.echo(line)

    def failure(self, command: str, code: Exit, message: str, detail: str | None = None) -> None:
        """Emit a failure. JSON to stdout in JSON mode, prose to stderr otherwise."""
        if self.json_mode:
            envelope = {
                "ok": False,
                "command": command,
                "exit_code": int(code),
                "error": code.name.lower(),
                "message": message,
                "dry_run": self.dry_run,
            }
            if detail:
                envelope["detail"] = detail
            typer.echo(json.dumps(envelope, indent=2, default=str))
            return
        typer.echo(f"error: {message}", err=True)
        if detail:
            typer.echo(f"  {detail}", err=True)

    def raw_json(self, payload: dict[str, Any]) -> None:
        """Emit a pre-built document verbatim (used by `check`, which owns its schema)."""
        json.dump(payload, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
