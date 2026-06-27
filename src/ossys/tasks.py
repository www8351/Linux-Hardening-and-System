"""Module:   ossys.tasks

Purpose:  Pure, side-effect-light task logic — the core that the CLI is a thin shell over.
          Counting, dice rolling, contact-file generation, and archive/backup creation.

Usage:    from ossys.tasks import archive_files, count_to, roll_cubes, save_details
          archive_files(["a.log", "b.log"], "backup.tgz")

Security notes:
    * The originals shelled out for everything (``os.system('echo ... > file')``,
      ``os.system('tar ...')``) — injectable *and* Linux-only.
    * Every task here is implemented with the Python standard library (``pathlib`` for
      file I/O, ``tarfile`` for archives). No shell is invoked, so filenames and field
      values can never be reinterpreted as commands, and the code runs cross-platform.
    * Inputs are validated (``n``/``rounds`` bounds, archive members must exist) so failures
      are explicit rather than silent or shell-dependent.
    * ``roll_cubes`` accepts an injectable ``random.Random`` so tests are deterministic;
      it is for demo/utility output, not security-sensitive randomness.
"""

from __future__ import annotations

import random
import tarfile
from dataclasses import dataclass
from pathlib import Path


def count_to(n: int) -> list[int]:
    """Return the list ``[1, 2, ..., n]``.

    Returning data (rather than printing) keeps the logic pure and testable; rendering is
    the CLI's responsibility. The original printed with a ``sleep`` baked in.
    """
    if n < 1:
        raise ValueError("n must be >= 1")
    return list(range(1, n + 1))


@dataclass(frozen=True)
class CubeRoll:
    """One round: the two values rolled. Immutable so results are safe to share/compare."""

    cube1: int
    cube2: int

    @property
    def is_match(self) -> bool:
        """True when both cubes show the same value."""
        return self.cube1 == self.cube2


def roll_cubes(rounds: int, *, sides: int = 10, rng: random.Random | None = None) -> list[CubeRoll]:
    """Roll two ``sides``-sided cubes ``rounds`` times.

    Args:
        rounds: Number of rounds to roll (must be >= 1).
        sides:  Faces per cube (default 10).
        rng:    Optional injected RNG for deterministic, reproducible tests. When None a
                fresh ``random.Random`` is used.
    """
    if rounds < 1:
        raise ValueError("rounds must be >= 1")
    r = rng or random.Random()
    return [CubeRoll(r.randint(1, sides), r.randint(1, sides)) for _ in range(rounds)]


def save_details(name: str, age: str, phone: str, path: str | Path) -> Path:
    """Write contact details to ``path`` and return the resulting path.

    Uses ``pathlib.Path.write_text`` instead of an ``echo > file`` shell-out, so the field
    values are written verbatim and never interpreted by a shell.
    """
    target = Path(path)
    target.write_text(
        f"Your Name is: {name}\nYour Age is: {age}\nYour Phone number is: {phone}\n",
        encoding="utf-8",
    )
    return target


def archive_files(files: list[str | Path], archive_path: str | Path) -> Path:
    """Create a gzip-compressed tarball of ``files`` at ``archive_path``.

    Built on the stdlib ``tarfile`` module rather than shelling out to ``tar``. Each member
    must exist (a missing file raises ``FileNotFoundError`` rather than producing a partial
    archive), and members are stored by basename to avoid leaking absolute host paths.
    """
    archive = Path(archive_path)
    with tarfile.open(archive, "w:gz") as tar:
        for f in files:
            p = Path(f)
            if not p.exists():
                raise FileNotFoundError(p)
            # arcname=p.name strips directory components from the stored path.
            tar.add(p, arcname=p.name)
    return archive
