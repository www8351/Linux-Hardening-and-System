"""Pure, testable task logic.

The originals shelled out for everything (`os.system('echo ... > file')`,
`os.system('tar ...')`), which was both injectable and Linux-only. These do the
same work in pure Python — no shell, no injection, cross-platform.
"""

from __future__ import annotations

import random
import tarfile
from dataclasses import dataclass
from pathlib import Path


def count_to(n: int) -> list[int]:
    """Return 1..n. (The original printed with a sleep; printing is the CLI's job.)"""
    if n < 1:
        raise ValueError("n must be >= 1")
    return list(range(1, n + 1))


@dataclass(frozen=True)
class CubeRoll:
    cube1: int
    cube2: int

    @property
    def is_match(self) -> bool:
        return self.cube1 == self.cube2


def roll_cubes(rounds: int, *, sides: int = 10, rng: random.Random | None = None) -> list[CubeRoll]:
    """Roll two cubes ``rounds`` times. Inject ``rng`` for deterministic tests."""
    if rounds < 1:
        raise ValueError("rounds must be >= 1")
    r = rng or random.Random()
    return [CubeRoll(r.randint(1, sides), r.randint(1, sides)) for _ in range(rounds)]


def save_details(name: str, age: str, phone: str, path: str | Path) -> Path:
    """Write contact details to a file using pathlib (no `echo` shell-out)."""
    target = Path(path)
    target.write_text(
        f"Your Name is: {name}\nYour Age is: {age}\nYour Phone number is: {phone}\n",
        encoding="utf-8",
    )
    return target


def archive_files(files: list[str | Path], archive_path: str | Path) -> Path:
    """Create a gzip tarball of ``files`` using the tarfile module (no `tar` shell-out)."""
    archive = Path(archive_path)
    with tarfile.open(archive, "w:gz") as tar:
        for f in files:
            p = Path(f)
            if not p.exists():
                raise FileNotFoundError(p)
            tar.add(p, arcname=p.name)
    return archive
