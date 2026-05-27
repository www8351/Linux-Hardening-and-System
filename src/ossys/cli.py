"""Non-interactive Typer CLI exposing the system tasks.

Replaces the old `while "True"` input() menus (menu_python.py / menu_bash.sh).
Everything is driven by arguments, so it runs in scripts and CI.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from . import __version__
from .system import add_user as _add_user
from .tasks import archive_files, count_to, roll_cubes, save_details

app = typer.Typer(help="Small system tasks (safe, non-interactive).", no_args_is_help=True)


@app.command()
def count(n: Annotated[int, typer.Argument(help="Count from 1 to N")]) -> None:
    """Print 1..N, one per line."""
    for i in count_to(n):
        typer.echo(i)


@app.command()
def cubes(
    rounds: Annotated[int, typer.Argument(help="How many rounds to roll")],
    seed: Annotated[int | None, typer.Option("--seed", help="Seed for reproducible rolls")] = None,
) -> None:
    """Roll two cubes each round and report matches."""
    import random

    rng = random.Random(seed) if seed is not None else None
    for roll in roll_cubes(rounds, rng=rng):
        verdict = "match!" if roll.is_match else "no match"
        typer.echo(f"{roll.cube1} vs {roll.cube2} — {verdict}")


@app.command()
def details(
    name: Annotated[str, typer.Option("--name")],
    age: Annotated[str, typer.Option("--age")],
    phone: Annotated[str, typer.Option("--phone")],
    out: Annotated[Path, typer.Option("--out", "-o")] = Path("details.txt"),
) -> None:
    """Write contact details to a file."""
    path = save_details(name, age, phone, out)
    typer.echo(f"Wrote {path}")


@app.command()
def archive(
    files: Annotated[list[Path], typer.Argument(help="Files to archive")],
    out: Annotated[Path, typer.Option("--out", "-o")] = Path("archive.tgz"),
) -> None:
    """Create a .tgz archive of the given files."""
    path = archive_files(list(files), out)
    typer.echo(f"Created {path}")


@app.command()
def useradd(
    username: Annotated[str, typer.Argument(help="Username to create (Linux)")],
    sudo: Annotated[bool, typer.Option("--sudo", help="Add to the sudo group")] = False,
) -> None:
    """Create a system user (Linux only)."""
    _add_user(username, sudo_group=sudo)
    typer.echo(f"Created user {username}")


@app.command()
def version() -> None:
    """Print the ossys version."""
    typer.echo(__version__)
