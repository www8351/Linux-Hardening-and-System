"""Tests for ossys.config — per-endpoint customisation.

Covers discovery order, profile overlay, hostname-glob selection, and the rule that a
malformed config is a hard failure rather than a silent fallback to defaults."""

from __future__ import annotations

from pathlib import Path

import pytest

from ossys import config
from ossys.config import load_settings
from ossys.exits import ConfigError

SAMPLE = """
[defaults]
mode = "auto"
allowed_roots = ["."]
timeout = 30

[profile.server]
hosts = ["srv-*"]
mode = "sudo"
allowed_roots = ["/var/lib/ossys"]
timeout = 60
json = true

[profile.workstation]
hosts = ["dev-*"]
mode = "user"
allowed_roots = ["~/ossys"]
"""


@pytest.fixture
def cfg(tmp_path: Path) -> Path:
    path = tmp_path / "ossys.toml"
    path.write_text(SAMPLE, encoding="utf-8")
    return path


def test_defaults_without_config_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """No config anywhere is valid — every caller can assume a populated Settings."""
    monkeypatch.setattr(config, "candidate_paths", lambda explicit=None: [tmp_path / "nope.toml"])
    settings = load_settings()
    assert settings.mode == "auto"
    assert settings.allowed_roots == ["."]
    assert settings.source is None


def test_explicit_profile_overlays_defaults(cfg: Path) -> None:
    settings = load_settings(path=cfg, profile="server")
    assert settings.profile == "server"
    assert settings.mode == "sudo"
    assert settings.allowed_roots == ["/var/lib/ossys"]
    assert settings.timeout == 60
    assert settings.json_output is True


def test_profile_selected_by_hostname_glob(monkeypatch: pytest.MonkeyPatch, cfg: Path) -> None:
    """One config file, many endpoints — this is what makes it fleet-deployable."""
    monkeypatch.setattr("ossys.config.socket.gethostname", lambda: "srv-web-01")
    settings = load_settings(path=cfg)
    assert settings.profile == "server"
    assert settings.mode == "sudo"


def test_hostname_glob_picks_the_matching_profile(
    monkeypatch: pytest.MonkeyPatch, cfg: Path
) -> None:
    monkeypatch.setattr("ossys.config.socket.gethostname", lambda: "dev-laptop")
    settings = load_settings(path=cfg)
    assert settings.profile == "workstation"
    assert settings.mode == "user"


def test_no_hostname_match_falls_back_to_defaults(
    monkeypatch: pytest.MonkeyPatch, cfg: Path
) -> None:
    monkeypatch.setattr("ossys.config.socket.gethostname", lambda: "unrelated-host")
    settings = load_settings(path=cfg)
    assert settings.profile == "defaults"
    assert settings.mode == "auto"


def test_env_var_selects_profile(monkeypatch: pytest.MonkeyPatch, cfg: Path) -> None:
    monkeypatch.setenv("OSSYS_PROFILE", "workstation")
    assert load_settings(path=cfg).profile == "workstation"


def test_unknown_profile_is_a_hard_error(cfg: Path) -> None:
    with pytest.raises(ConfigError, match="unknown profile"):
        load_settings(path=cfg, profile="nope")


def test_missing_explicit_config_is_an_error(tmp_path: Path) -> None:
    """If the operator named a file, running with different settings is worse than failing."""
    with pytest.raises(ConfigError, match="not found"):
        load_settings(path=tmp_path / "absent.toml")


def test_malformed_toml_is_a_hard_error(tmp_path: Path) -> None:
    """Never silently fall back to defaults — that ships a host with controls the operator
    believes are active."""
    bad = tmp_path / "ossys.toml"
    bad.write_text("[defaults\nmode = ", encoding="utf-8")
    with pytest.raises(ConfigError, match="malformed TOML"):
        load_settings(path=bad)


def test_invalid_mode_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "ossys.toml"
    bad.write_text('[defaults]\nmode = "superuser"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="must be one of"):
        load_settings(path=bad)


def test_negative_timeout_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "ossys.toml"
    bad.write_text("[defaults]\ntimeout = -1\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="must be positive"):
        load_settings(path=bad)


def test_wrong_type_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "ossys.toml"
    bad.write_text('[defaults]\nallowed_roots = "/var/lib/ossys"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="list of strings"):
        load_settings(path=bad)


def test_discovery_order_prefers_user_config_over_etc() -> None:
    """The privileged and unprivileged paths must land on different files by default."""
    chain = [str(p) for p in config.candidate_paths()]
    home_idx = next(i for i, p in enumerate(chain) if ".config" in p)
    etc_idx = next(i for i, p in enumerate(chain) if "etc" in p)
    assert home_idx < etc_idx


# --- webhook ------------------------------------------------------------------------------


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "ossys.toml"
    path.write_text(body, encoding="utf-8")
    return path


def test_webhook_defaults_are_closed(tmp_path: Path) -> None:
    """No URL, https-only, no detail egress, no token — the safe posture."""
    settings = load_settings(path=_write(tmp_path, "[defaults]\n"))
    assert settings.webhook_url == ""
    assert settings.webhook_allow_http is False
    assert settings.webhook_include_detail is False
    assert settings.webhook_token_env == ""


def test_webhook_table_is_parsed(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path,
        "[defaults.webhook]\n"
        'url = "https://collector.example/hook"\n'
        "timeout = 3\n"
        "include_detail = true\n"
        'token_env = "OSSYS_TOKEN"\n',
    )
    settings = load_settings(path=cfg)
    assert settings.webhook_url == "https://collector.example/hook"
    assert settings.webhook_timeout == 3.0
    assert settings.webhook_include_detail is True
    assert settings.webhook_token_env == "OSSYS_TOKEN"


def test_webhook_url_validated_at_load_time(tmp_path: Path) -> None:
    """Caught at deployment, not during the first real failure — the worst moment to learn
    the alerting is broken."""
    cfg = _write(tmp_path, '[defaults.webhook]\nurl = "http://collector.example/hook"\n')
    with pytest.raises(ConfigError, match="https"):
        load_settings(path=cfg)


def test_webhook_http_allowed_with_opt_in(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path,
        '[defaults.webhook]\nurl = "http://collector.example/hook"\nallow_http = true\n',
    )
    assert load_settings(path=cfg).webhook_url.startswith("http://")


def test_webhook_credentials_in_url_rejected(tmp_path: Path) -> None:
    cfg = _write(tmp_path, '[defaults.webhook]\nurl = "https://u:p@collector.example/h"\n')
    with pytest.raises(ConfigError, match="credentials"):
        load_settings(path=cfg)


def test_webhook_unknown_key_rejected(tmp_path: Path) -> None:
    """A misspelled `on_failuer = false` would otherwise leave alerting armed while the
    operator believes it is off."""
    cfg = _write(tmp_path, "[defaults.webhook]\non_failuer = false\n")
    with pytest.raises(ConfigError, match="unknown keys"):
        load_settings(path=cfg)


def test_webhook_negative_timeout_rejected(tmp_path: Path) -> None:
    cfg = _write(tmp_path, "[defaults.webhook]\ntimeout = -1\n")
    with pytest.raises(ConfigError, match="must be positive"):
        load_settings(path=cfg)


def test_profile_can_override_webhook(tmp_path: Path) -> None:
    cfg = _write(
        tmp_path,
        '[defaults.webhook]\nurl = "https://default.example/h"\n\n'
        '[profile.server.webhook]\nurl = "https://server.example/h"\n',
    )
    assert load_settings(path=cfg, profile="server").webhook_url == "https://server.example/h"
