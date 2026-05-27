"""Pure task logic."""

from __future__ import annotations

import random
import tarfile
from pathlib import Path

import pytest

from ossys.tasks import archive_files, count_to, roll_cubes, save_details


def test_count_to() -> None:
    assert count_to(3) == [1, 2, 3]


def test_count_to_rejects_zero() -> None:
    with pytest.raises(ValueError):
        count_to(0)


def test_roll_cubes_is_deterministic_with_seed() -> None:
    a = roll_cubes(5, rng=random.Random(42))
    b = roll_cubes(5, rng=random.Random(42))
    assert a == b
    assert len(a) == 5


def test_cube_match_flag() -> None:
    rolls = roll_cubes(50, sides=1, rng=random.Random(0))  # sides=1 → always equal
    assert all(r.is_match for r in rolls)


def test_save_details(tmp_path: Path) -> None:
    out = save_details("Refael", "30", "555", tmp_path / "d.txt")
    content = out.read_text(encoding="utf-8")
    assert "Refael" in content and "555" in content


def test_archive_files(tmp_path: Path) -> None:
    f1 = tmp_path / "a.txt"
    f1.write_text("hi", encoding="utf-8")
    archive = archive_files([f1], tmp_path / "out.tgz")
    with tarfile.open(archive) as tar:
        assert tar.getnames() == ["a.txt"]


def test_archive_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        archive_files([tmp_path / "nope.txt"], tmp_path / "out.tgz")
