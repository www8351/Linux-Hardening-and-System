"""Tests for ossys.tasks. Proves the pure, shell-free task logic: input bounds are enforced
at both ends, dice rolls are reproducible under a seeded RNG, output paths are contained,
and a failed archive leaves nothing behind."""

from __future__ import annotations

import random
import tarfile
from pathlib import Path

import pytest

from ossys.exits import ValidationError
from ossys.tasks import archive_files, count_to, roll_cubes, save_details
from ossys.validate import MAX_COUNT


def test_count_to() -> None:
    assert list(count_to(3)) == [1, 2, 3]


def test_count_to_rejects_zero() -> None:
    with pytest.raises(ValidationError):
        list(count_to(0))


def test_count_to_rejects_absurd_upper_bound() -> None:
    """OSSYS-SEC-008: an unbounded n allocated until the OOM killer stepped in."""
    with pytest.raises(ValidationError):
        list(count_to(MAX_COUNT + 1))


def test_count_to_is_lazy() -> None:
    """Validation must happen eagerly enough to be useful, but not materialise the range."""
    gen = count_to(MAX_COUNT)
    assert next(iter(gen)) == 1


def test_roll_cubes_is_deterministic_with_seed() -> None:
    a = roll_cubes(5, rng=random.Random(42))
    b = roll_cubes(5, rng=random.Random(42))
    assert a == b
    assert len(a) == 5


def test_cube_match_flag() -> None:
    rolls = roll_cubes(50, sides=2, rng=random.Random(0))
    assert all(r.cube1 in (1, 2) and r.cube2 in (1, 2) for r in rolls)


def test_roll_cubes_rejects_bad_sides() -> None:
    """OSSYS-SEC-012: sides < 2 previously surfaced as an opaque stdlib ValueError."""
    with pytest.raises(ValidationError):
        roll_cubes(1, sides=1)


def test_save_details(tmp_path: Path) -> None:
    out = save_details("Refael", "30", "555", tmp_path / "d.txt", allowed_roots=[tmp_path])
    content = out.read_text(encoding="utf-8")
    assert "Refael" in content
    assert "555" in content


def test_save_details_rejects_path_outside_allowed_roots(tmp_path: Path) -> None:
    """OSSYS-SEC-001 (HIGH): --out could name any path, including under sudo."""
    outside = tmp_path.parent / "escaped.txt"
    with pytest.raises(ValidationError, match="outside the allowed roots"):
        save_details("a", "1", "2", outside, allowed_roots=[tmp_path])


def test_save_details_rejects_traversal(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(ValidationError, match="outside the allowed roots"):
        save_details("a", "1", "2", root / ".." / "escaped.txt", allowed_roots=[root])


def test_save_details_rejects_newline_injection(tmp_path: Path) -> None:
    """OSSYS-SEC-013: a newline in --name forged an extra record."""
    with pytest.raises(ValidationError, match="control characters"):
        save_details(
            "Alice\nYour Age is: 99", "30", "555", tmp_path / "d.txt", allowed_roots=[tmp_path]
        )


def test_save_details_does_not_follow_symlink(tmp_path: Path) -> None:
    """OSSYS-SEC-001: the pre-created-symlink attack on the default output path."""
    secret = tmp_path / "secret.txt"
    secret.write_text("original", encoding="utf-8")
    link = tmp_path / "details.txt"
    try:
        link.symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this platform")

    with pytest.raises(ValidationError, match="symlink"):
        save_details("a", "1", "2", link, allowed_roots=[tmp_path])
    assert secret.read_text(encoding="utf-8") == "original"


def test_archive_files(tmp_path: Path) -> None:
    f1 = tmp_path / "a.txt"
    f1.write_text("hi", encoding="utf-8")
    archive = archive_files([f1], tmp_path / "out.tgz", allowed_roots=[tmp_path])
    with tarfile.open(archive) as tar:
        assert tar.getnames() == ["a.txt"]


def test_archive_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        archive_files([tmp_path / "nope.txt"], tmp_path / "out.tgz", allowed_roots=[tmp_path])


def test_archive_leaves_nothing_behind_on_failure(tmp_path: Path) -> None:
    """OSSYS-SEC-014: a failed run left a truncated .tgz indistinguishable from a good one.

    The pre-existing test asserted only the exception and passed straight over this bug.
    """
    good = tmp_path / "a.txt"
    good.write_text("hi", encoding="utf-8")
    out = tmp_path / "out.tgz"

    with pytest.raises(ValidationError):
        archive_files([good, tmp_path / "nope.txt"], out, allowed_roots=[tmp_path])

    assert not out.exists()
    assert list(tmp_path.glob(".*tmp")) == []


def test_archive_rejects_directory_member(tmp_path: Path) -> None:
    """OSSYS-SEC-003: exists() accepted dirs and tar.add recursed into them silently."""
    subdir = tmp_path / "sub"
    subdir.mkdir()
    (subdir / "x.txt").write_text("x", encoding="utf-8")
    with pytest.raises(ValidationError, match="not a regular file"):
        archive_files([subdir], tmp_path / "out.tgz", allowed_roots=[tmp_path])


def test_archive_rejects_basename_collision(tmp_path: Path) -> None:
    """OSSYS-SEC-004: two same-named files silently became one member at restore time."""
    a = tmp_path / "one"
    b = tmp_path / "two"
    a.mkdir()
    b.mkdir()
    (a / "config.yml").write_text("a", encoding="utf-8")
    (b / "config.yml").write_text("b", encoding="utf-8")

    with pytest.raises(ValidationError, match="collision"):
        archive_files(
            [a / "config.yml", b / "config.yml"], tmp_path / "out.tgz", allowed_roots=[tmp_path]
        )


def test_archive_rejects_output_outside_allowed_roots(tmp_path: Path) -> None:
    """OSSYS-SEC-002 (HIGH): -o could clobber any path, e.g. /etc/shadow, under sudo."""
    f1 = tmp_path / "a.txt"
    f1.write_text("hi", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(ValidationError, match="outside the allowed roots"):
        archive_files([f1], tmp_path / "escaped.tgz", allowed_roots=[root])
