"""Module:   ossys.tasks

Purpose:  Pure, side-effect-light task logic — the core that the CLI is a thin shell over.
          Counting, dice rolling, contact-file generation, and archive/backup creation.
          These are the *unprivileged* operations: they run identically on both automation
          paths, root or not.

Usage:    from ossys.tasks import archive_files, count_to, roll_cubes, save_details
          archive_files(["a.log", "b.log"], "backup.tgz", allowed_roots=[Path.cwd()])

Security notes:
    * The originals shelled out for everything (``os.system('echo ... > file')``,
      ``os.system('tar ...')``) — injectable *and* Linux-only. Everything here is stdlib
      (``pathlib`` for file I/O, ``tarfile`` for archives); no shell is ever invoked.
    * OSSYS-SEC-001 / OSSYS-SEC-002 (both HIGH) — destination paths were previously passed
      straight to ``write_text`` / ``tarfile.open``. Under sudo that was an arbitrary
      root-owned file write, and both calls followed symlinks, so an attacker who could
      pre-create the default ``details.txt`` as a symlink turned the *default* invocation
      into a privileged overwrite. Both now route through ``validate_output_path``, which
      refuses symlinks and enforces containment inside the endpoint's allowed roots.
    * OSSYS-SEC-014 — writes go to a temporary file in the destination directory and are
      moved into place with ``os.replace`` only on success, so a failed run cannot leave a
      truncated artifact that looks like a successful one.
    * OSSYS-SEC-003 / -004 — archive members must be regular files (``exists()`` accepted
      directories, and ``tarfile.add`` recurses into them), and basename collisions are
      rejected rather than silently dropping a file at restore time.
    * OSSYS-SEC-008 / -012 — counts, rounds and die faces are bounded at both ends.
    * ``roll_cubes`` accepts an injectable ``random.Random`` so tests are deterministic;
      it is for demo/utility output, not security-sensitive randomness.
"""

from __future__ import annotations

import os
import random
import tarfile
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .validate import (
    MAX_COUNT,
    MAX_ROUNDS,
    validate_archive_members,
    validate_int_range,
    validate_output_path,
    validate_sides,
    validate_text_field,
)


def count_to(n: int) -> Iterator[int]:
    """Yield ``1, 2, ..., n``.

    A generator rather than a list: `list(range(1, 10**10))` allocated until the OOM killer
    stepped in (OSSYS-SEC-008). The upper bound in `validate_int_range` is the real fix;
    yielding means even the permitted maximum costs no memory. The CLI already consumed
    this lazily, so the change is source-compatible.
    """
    validate_int_range(n, name="n", minimum=1, maximum=MAX_COUNT)
    yield from range(1, n + 1)


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
        rounds: Number of rounds to roll (1..MAX_ROUNDS).
        sides:  Faces per cube (2..MAX_SIDES; default 10).
        rng:    Optional injected RNG for deterministic, reproducible tests.
    """
    validate_int_range(rounds, name="rounds", minimum=1, maximum=MAX_ROUNDS)
    validate_sides(sides)
    r = rng or random.Random()
    return [CubeRoll(r.randint(1, sides), r.randint(1, sides)) for _ in range(rounds)]


def _atomic_write_text(target: Path, content: str) -> Path:
    """Write ``content`` to ``target`` atomically, without ever following a symlink.

    `mkstemp` creates the temp file with O_CREAT|O_EXCL|O_NOFOLLOW semantics and mode 0600,
    in the *destination directory* so the final `os.replace` is a same-filesystem rename and
    therefore atomic. A crash or exception leaves the original file untouched rather than
    truncated (OSSYS-SEC-014).
    """
    fd, tmp_name = tempfile.mkstemp(
        dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return target


def save_details(
    name: str,
    age: str,
    phone: str,
    path: str | Path,
    *,
    allowed_roots: list[Path] | list[str] | None = None,
) -> Path:
    """Write contact details to ``path`` and return the resolved path.

    The destination is authorised before anything is written, and the field values are
    checked for control characters so a newline in ``--name`` cannot forge additional
    records (OSSYS-SEC-013).
    """
    validate_text_field(name, name="name")
    validate_text_field(age, name="age")
    validate_text_field(phone, name="phone")
    target = validate_output_path(path, allowed_roots=allowed_roots)

    content = f"Your Name is: {name}\nYour Age is: {age}\nYour Phone number is: {phone}\n"
    return _atomic_write_text(target, content)


def archive_files(
    files: list[str | Path],
    archive_path: str | Path,
    *,
    allowed_roots: list[Path] | list[str] | None = None,
) -> Path:
    """Create a gzip-compressed tarball of ``files`` at ``archive_path``.

    Members are validated as a set *before* the destination is opened, so a bad input list
    cannot leave a partial archive behind. Members are stored by basename to avoid leaking
    absolute host paths; collisions are rejected up front rather than silently losing a file
    at restore time.
    """
    members = validate_archive_members(files)
    target = validate_output_path(archive_path, allowed_roots=allowed_roots)

    fd, tmp_name = tempfile.mkstemp(
        dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp"
    )
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        # recursive=False is belt-and-braces: validate_archive_members already rejects
        # directories, but the default (True) is the dangerous one and should not be relied
        # on being unreachable.
        with tarfile.open(tmp, "w:gz") as tar:
            for p in members:
                tar.add(p, arcname=p.name, recursive=False)
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return target
