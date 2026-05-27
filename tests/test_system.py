"""Privileged ops — subprocess + tool lookup fully mocked (nothing real runs)."""

from __future__ import annotations

import pytest

from ossys import system


def test_validate_username_accepts_valid() -> None:
    assert system.validate_username("refael") == "refael"


@pytest.mark.parametrize("bad", ["bob; rm -rf /", "Bob", "1abc", "", "a" * 40])
def test_validate_username_rejects_bad(bad: str) -> None:
    with pytest.raises(ValueError):
        system.validate_username(bad)


def test_add_user_uses_list_args_no_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    monkeypatch.setattr(system.shutil, "which", lambda tool: f"/usr/sbin/{tool}")
    monkeypatch.setattr(
        system.subprocess,
        "run",
        lambda cmd, check: calls.append(cmd),  # type: ignore[misc]
    )

    system.add_user("refael", sudo_group=True)

    assert calls == [
        ["sudo", "useradd", "refael"],
        ["sudo", "usermod", "-aG", "sudo", "refael"],
    ]


def test_add_user_rejects_injection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(system.shutil, "which", lambda tool: f"/usr/sbin/{tool}")
    with pytest.raises(ValueError):
        system.add_user("bob; rm -rf /")


def test_add_user_missing_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(system.shutil, "which", lambda tool: None)
    with pytest.raises(system.SystemError_):
        system.add_user("refael")
