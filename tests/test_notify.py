"""Tests for ossys.notify — the optional failure webhook.

The invariants that matter here are negative ones: disabled by default, never raises, never
changes the exit code, never sends on dry-run, never leaks command stderr unless asked, and
never opens a non-http scheme. No real network call is made anywhere in this file."""

from __future__ import annotations

import json
import ssl
import urllib.error
from typing import Any

import pytest

from ossys.config import Settings
from ossys.exits import Exit
from ossys.notify import (
    MAX_DETAIL_CHARS,
    WebhookConfigError,
    WebhookResult,
    build_payload,
    notify_failure,
    validate_webhook_url,
)


@pytest.fixture
def sent() -> list[dict[str, Any]]:
    """Collector for intercepted POSTs."""
    return []


@pytest.fixture
def fake_post(monkeypatch: pytest.MonkeyPatch, sent: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def _post(url: str, payload: dict[str, Any], *, timeout: float, token: str | None) -> int:
        sent.append({"url": url, "payload": payload, "timeout": timeout, "token": token})
        return 200

    monkeypatch.setattr("ossys.notify._post", _post)
    return sent


def _settings(**kw: Any) -> Settings:
    base = Settings(webhook_url="https://collector.example/hook")
    for key, value in kw.items():
        setattr(base, key, value)
    return base


# --- URL validation -----------------------------------------------------------------------


def test_https_accepted() -> None:
    assert validate_webhook_url("https://collector.example/hook")


def test_http_rejected_by_default() -> None:
    with pytest.raises(WebhookConfigError, match="https"):
        validate_webhook_url("http://collector.example/hook")


def test_http_allowed_with_explicit_opt_in() -> None:
    assert validate_webhook_url("http://collector.example/hook", allow_http=True)


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/x",
        "gopher://example.com/",
        "data:text/plain,hi",
    ],
)
def test_non_http_schemes_rejected(url: str) -> None:
    """This is what keeps urlopen away from file:// — the class ruff S310 warns about."""
    with pytest.raises(WebhookConfigError):
        validate_webhook_url(url, allow_http=True)


def test_url_without_host_rejected() -> None:
    with pytest.raises(WebhookConfigError, match="no host"):
        validate_webhook_url("https:///nohost")


def test_embedded_credentials_rejected() -> None:
    """A URL that travels in a 0644 config file must not carry a secret."""
    with pytest.raises(WebhookConfigError, match="token_env"):
        validate_webhook_url("https://user:pass@collector.example/hook")


# --- gating -------------------------------------------------------------------------------


def test_disabled_when_no_url_configured(fake_post: list[dict[str, Any]]) -> None:
    """Default posture: no URL means no call, no DNS lookup, no socket."""
    result = notify_failure(Settings(), command="count", exit_code=10, message="bad")
    assert result == WebhookResult.skipped("no webhook configured")
    assert fake_post == []


def test_disabled_when_on_failure_false(fake_post: list[dict[str, Any]]) -> None:
    result = notify_failure(
        _settings(webhook_on_failure=False), command="count", exit_code=10, message="bad"
    )
    assert result.attempted is False
    assert fake_post == []


@pytest.mark.parametrize("code", [int(Exit.OK), int(Exit.NOOP)])
def test_success_outcomes_do_not_notify(code: int, fake_post: list[dict[str, Any]]) -> None:
    """Exit 40 is an idempotent success — paging on it would fire every scheduled run."""
    result = notify_failure(_settings(), command="useradd", exit_code=code, message="fine")
    assert result.attempted is False
    assert fake_post == []


def test_dry_run_suppresses_the_notification(fake_post: list[dict[str, Any]]) -> None:
    """A dry run must produce no externally visible side effects, and an alert is one."""
    result = notify_failure(
        _settings(), command="useradd", exit_code=30, message="boom", dry_run=True
    )
    assert result.attempted is False
    assert "dry-run" in result.reason
    assert fake_post == []


def test_failure_is_sent(fake_post: list[dict[str, Any]]) -> None:
    result = notify_failure(_settings(), command="useradd", exit_code=30, message="boom")
    assert result.delivered is True
    assert result.status == 200
    assert len(fake_post) == 1
    assert fake_post[0]["url"] == "https://collector.example/hook"


# --- payload ------------------------------------------------------------------------------


def test_payload_shape_is_flat_and_routable(fake_post: list[dict[str, Any]]) -> None:
    notify_failure(_settings(profile="server"), command="archive", exit_code=30, message="boom")
    payload = fake_post[0]["payload"]

    assert payload["source"] == "ossys"
    assert payload["command"] == "archive"
    assert payload["exit_code"] == 30
    assert payload["error"] == "external"
    assert payload["profile"] == "server"
    assert payload["host"]
    assert payload["timestamp"]
    json.dumps(payload)  # must be serialisable as-is


def test_detail_omitted_by_default(fake_post: list[dict[str, Any]]) -> None:
    """Command stderr can carry usernames, paths and host layout. Egress is opt-in."""
    notify_failure(
        _settings(), command="useradd", exit_code=30, message="boom", detail="useradd: /etc/secret"
    )
    assert "detail" not in fake_post[0]["payload"]


def test_detail_included_when_opted_in(fake_post: list[dict[str, Any]]) -> None:
    notify_failure(
        _settings(webhook_include_detail=True),
        command="useradd",
        exit_code=30,
        message="boom",
        detail="stderr text",
    )
    assert fake_post[0]["payload"]["detail"] == "stderr text"


def test_detail_is_truncated() -> None:
    payload = build_payload(
        command="x",
        exit_code=30,
        message="m",
        detail="A" * (MAX_DETAIL_CHARS + 500),
        settings=_settings(webhook_include_detail=True),
        include_detail=True,
    )
    assert len(payload["detail"]) == MAX_DETAIL_CHARS
    assert payload["detail_truncated"] is True


def test_unknown_exit_code_does_not_explode() -> None:
    payload = build_payload(
        command="x",
        exit_code=999,
        message="m",
        detail=None,
        settings=_settings(),
        include_detail=False,
    )
    assert payload["error"] == "unknown"


# --- secrets ------------------------------------------------------------------------------


def test_token_read_from_environment_not_config(
    monkeypatch: pytest.MonkeyPatch, fake_post: list[dict[str, Any]]
) -> None:
    monkeypatch.setenv("OSSYS_TEST_TOKEN", "s3cret")
    notify_failure(
        _settings(webhook_token_env="OSSYS_TEST_TOKEN"),
        command="x",
        exit_code=30,
        message="boom",
    )
    assert fake_post[0]["token"] == "s3cret"


def test_token_absent_when_env_var_unset(
    monkeypatch: pytest.MonkeyPatch, fake_post: list[dict[str, Any]]
) -> None:
    monkeypatch.delenv("OSSYS_TEST_TOKEN", raising=False)
    notify_failure(
        _settings(webhook_token_env="OSSYS_TEST_TOKEN"),
        command="x",
        exit_code=30,
        message="boom",
    )
    assert fake_post[0]["token"] is None


def test_token_never_appears_in_the_payload(
    monkeypatch: pytest.MonkeyPatch, fake_post: list[dict[str, Any]]
) -> None:
    monkeypatch.setenv("OSSYS_TEST_TOKEN", "s3cret")
    notify_failure(
        _settings(webhook_token_env="OSSYS_TEST_TOKEN"),
        command="x",
        exit_code=30,
        message="boom",
    )
    assert "s3cret" not in json.dumps(fake_post[0]["payload"])


# --- failure isolation ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        urllib.error.URLError("dns failure"),
        TimeoutError("timed out"),
        OSError("connection refused"),
        ssl.SSLError("handshake failed"),
    ],
)
def test_transport_failures_are_swallowed(monkeypatch: pytest.MonkeyPatch, exc: Exception) -> None:
    """A dead collector must never displace the failure it was reporting on."""

    def _boom(*a: Any, **kw: Any) -> int:
        raise exc

    monkeypatch.setattr("ossys.notify._post", _boom)
    result = notify_failure(_settings(), command="x", exit_code=30, message="boom")

    assert result.attempted is True
    assert result.delivered is False
    assert result.reason


def test_http_error_is_recorded_with_status(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*a: Any, **kw: Any) -> int:
        raise urllib.error.HTTPError("https://x/", 503, "unavailable", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr("ossys.notify._post", _boom)
    result = notify_failure(_settings(), command="x", exit_code=30, message="boom")

    assert result.status == 503
    assert result.delivered is False


def test_non_2xx_status_is_not_delivered(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ossys.notify._post", lambda *a, **kw: 302)
    result = notify_failure(_settings(), command="x", exit_code=30, message="boom")
    assert result.delivered is False
    assert result.status == 302


def test_bad_url_reported_not_raised(fake_post: list[dict[str, Any]]) -> None:
    """Validation happens at load time too, but a bad URL reaching here must not raise."""
    result = notify_failure(
        _settings(webhook_url="file:///etc/passwd"), command="x", exit_code=30, message="boom"
    )
    assert result.attempted is False
    assert "scheme" in result.reason
    assert fake_post == []


def test_timeout_is_passed_through(fake_post: list[dict[str, Any]]) -> None:
    """Alerting must not stall the run it reports on."""
    notify_failure(_settings(webhook_timeout=2.5), command="x", exit_code=30, message="boom")
    assert fake_post[0]["timeout"] == 2.5


def test_module_never_calls_urlopen_without_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guard against a future refactor that bypasses the scheme allow-list."""
    called: list[str] = []

    def _urlopen(request: Any, **kw: Any) -> Any:
        called.append(request.full_url)
        raise urllib.error.URLError("blocked in test")

    monkeypatch.setattr("ossys.notify.urllib.request.urlopen", _urlopen)
    notify_failure(
        _settings(webhook_url="file:///etc/passwd"), command="x", exit_code=30, message="boom"
    )
    assert called == [], "urlopen must not be reached for a rejected scheme"
