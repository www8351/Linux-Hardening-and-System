"""Package:  ossys_plugin_demo

Purpose:  A minimal, working ossys plugin — the template to copy when adding a new admin
          domain (Docker management, backups, log rotation) without touching ossys core.

Install:  pip install -e examples/ossys-plugin-demo
          ossys plugins           # shows it, and which distribution it came from
          ossys demo hello

How it works:
    pyproject.toml declares an entry point in the ``ossys.plugins`` group:

        [project.entry-points."ossys.plugins"]
        demo = "ossys_plugin_demo:app"

    ossys discovers that at startup and mounts ``app`` as ``ossys demo ...``. The entry
    point may resolve to a ``typer.Typer`` instance, or to a zero-argument callable
    returning one when construction should stay lazy.

Contract a real plugin should honour — none of it is enforced by core, so a plugin that
ignores these silently makes the endpoint less safe than ossys claims to be:

    * **Reuse the validators.** Import ``ossys.validate`` rather than writing your own
      checks. ``validate_output_path`` is what keeps ``--out`` inside the endpoint's
      configured ``allowed_roots``; a plugin that calls ``Path.write_text`` directly
      reopens the exact HIGH finding (OSSYS-SEC-001) that layer exists to close.
    * **Reuse the privilege layer.** Run external commands through ``ossys.privilege.run``,
      which pins the resolved absolute path, applies a timeout, closes stdin and passes a
      minimal environment. Never call ``subprocess`` directly, and never with ``shell=True``.
    * **Reuse the exit taxonomy.** Raise from ``ossys.exits`` so callers keep getting
      documented, branchable exit codes instead of a traceback and exit 1.
    * **Stay non-interactive.** No prompts, no ``input()``, no TTY assumptions. Plugins run
      under cron and systemd timers like everything else.
    * **Be idempotent.** Raise ``AlreadyDone`` (exit 40) when the requested state already
      holds, so re-running a timer is a no-op rather than an error.

Security note: being installed is being trusted. Once ossys loads this package it runs with
the full privilege of the ossys process, which on the privileged automation path is root.
That is why ``[defaults.plugins] allowlist`` exists and why ``ossys check`` reports the
distribution behind every mounted plugin.
"""

from __future__ import annotations

from typing import Annotated

import typer

from ossys.exits import AlreadyDone
from ossys.validate import validate_text_field

__version__ = "0.1.0"

app = typer.Typer(help="Demo plugin — a template for new ossys admin domains.")


@app.command()
def hello(
    name: Annotated[str, typer.Argument(help="Who to greet")] = "world",
    already: Annotated[
        bool, typer.Option("--already", help="Simulate an idempotent no-op (exit 40)")
    ] = False,
) -> None:
    """Greet someone. Demonstrates validator reuse and the idempotency signal."""
    # Reusing the core validator rather than trusting the argument: this is the habit the
    # whole plugin contract is built on.
    validate_text_field(name, name="name")

    if already:
        raise AlreadyDone(f"{name} has already been greeted; nothing to do")

    typer.echo(f"hello, {name}")
