"""Module:   ossys.notify

Purpose:  Optional failure notification. Posts a small JSON document to a config-gated URL
          when a scheduled run fails, so an unattended fleet surfaces problems without
          someone tailing journals.

Usage:    from ossys.notify import notify_failure
          notify_failure(settings, command="useradd", exit_code=Exit.EXTERNAL,
                         message="command failed with exit 9: useradd")

Config:   [defaults.webhook]
          url            = "https://collector.internal/ossys"   # empty disables entirely
          on_failure     = true
          timeout        = 5
          include_detail = false     # see "data egress" below
          token_env      = "OSSYS_WEBHOOK_TOKEN"
          allow_http     = false

Security notes:
    * **Disabled by default.** An empty ``url`` means no network call, no DNS lookup, no
      socket. A hardening tool must not phone home unless explicitly told to.
    * **Never changes the outcome.** Every failure inside this module is caught and recorded
      in the returned ``WebhookResult``. A dead collector must not turn a validation error
      (exit 10) into something else, and must not mask a real failure with a network one.
      The notification is a side channel, not part of the result.
    * **Never hangs.** A hard timeout on connect+read. This module exists to serve unattended
      runs; a webhook that blocks would defeat the same non-interactive guarantee that
      OSSYS-SEC-006 was about.
    * **Scheme allow-list.** Only https (http requires explicit ``allow_http``). This is what
      keeps ``urlopen`` away from ``file://``, ``ftp://`` and friends — the exact class ruff's
      S310 warns about. Credentials embedded in the URL are rejected, because a URL that
      travels in a config file should not carry a secret.
    * **Secrets come from the environment, not the config file.** ``token_env`` names an
      environment variable; the token itself is never written to ``ossys.toml``, which is
      mode 0644 and readable by every local user.
    * **TLS verification is always on.** An explicit default SSL context is passed rather than
      relying on the ambient default, and there is deliberately no "insecure" switch.
    * **Data egress is opt-in.** ``detail`` often carries an external command's stderr, which
      can contain usernames, paths and host layout. It is omitted unless ``include_detail``
      is set, and truncated when included. Shipping raw stderr to a third-party endpoint by
      default is precisely the quiet egress this tool should not do.
    * Private and link-local destinations are **not** blocked. The intended deployment is a
      fleet reporting to an internal collector, so SSRF-style filtering would break the
      normal case; the URL is operator-set in a root-owned config, not attacker-supplied.
      Recorded in DECISIONS.md D-017.
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from . import __version__
from .exits import Exit

if TYPE_CHECKING:
    from .config import Settings

DEFAULT_WEBHOOK_TIMEOUT = 5.0
MAX_DETAIL_CHARS = 2000
USER_AGENT = f"ossys/{__version__}"

# Exit codes that are *not* failures. 40 (NOOP) is an idempotent success — notifying on it
# would page someone every time a scheduled job correctly did nothing (DECISIONS.md D-010).
_SUCCESS_CODES = frozenset({int(Exit.OK), int(Exit.NOOP)})


@dataclass(frozen=True)
class WebhookResult:
    """What happened when (or whether) the notification was attempted.

    Returned rather than raised: the caller is an error path already, and a failed
    notification must never displace the original failure.
    """

    attempted: bool
    delivered: bool
    status: int | None = None
    reason: str = ""

    @classmethod
    def skipped(cls, reason: str) -> WebhookResult:
        return cls(attempted=False, delivered=False, reason=reason)


class WebhookConfigError(ValueError):
    """The configured webhook URL is unusable. Raised only by explicit validation."""


def validate_webhook_url(url: str, *, allow_http: bool = False) -> str:
    """Validate a webhook URL against the scheme allow-list. Raises on anything unusable.

    Called both at send time and by ``ossys check``, so a typo'd or downgraded URL is caught
    at deployment rather than on the first failure — which is the worst possible moment to
    discover the alerting is broken.
    """
    parsed = urllib.parse.urlsplit(url)

    allowed = {"https", "http"} if allow_http else {"https"}
    if parsed.scheme not in allowed:
        raise WebhookConfigError(
            f"webhook URL scheme must be {' or '.join(sorted(allowed))}, got {parsed.scheme!r}"
            + ("" if allow_http else " (set webhook.allow_http = true to permit plain http)")
        )
    if not parsed.hostname:
        raise WebhookConfigError(f"webhook URL has no host: {url!r}")
    if parsed.username or parsed.password:
        raise WebhookConfigError(
            "webhook URL must not embed credentials; use webhook.token_env instead"
        )
    return url


def build_payload(
    *,
    command: str,
    exit_code: int,
    message: str,
    detail: str | None,
    settings: Settings,
    include_detail: bool,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Assemble the notification body.

    Flat and small on purpose — a collector should be able to route on ``host`` and
    ``exit_code`` without walking a nested structure.
    """
    try:
        error_name = Exit(exit_code).name.lower()
    except ValueError:
        error_name = "unknown"

    payload: dict[str, Any] = {
        "source": "ossys",
        "version": __version__,
        "host": socket.gethostname(),
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "command": command,
        "exit_code": exit_code,
        "error": error_name,
        "message": message,
        "profile": settings.profile,
    }

    if include_detail and detail:
        truncated = detail[:MAX_DETAIL_CHARS]
        payload["detail"] = truncated
        if len(detail) > MAX_DETAIL_CHARS:
            payload["detail_truncated"] = True

    return payload


def _post(url: str, payload: dict[str, Any], *, timeout: float, token: str | None) -> int:
    """POST ``payload`` as JSON and return the HTTP status. Caller handles all errors."""
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # S310 (audit URL open) is satisfied by validate_webhook_url, which every caller
    # path runs first: the scheme is restricted to http/https before this line is
    # reachable, so neither Request nor urlopen can be steered at file:// or ftp://.
    request = urllib.request.Request(  # noqa: S310
        url, data=body, headers=headers, method="POST"
    )
    # Explicit default context: TLS verification stays on, and there is no switch to disable
    # it. create_default_context() checks hostnames and the system trust store.
    context = ssl.create_default_context()

    with urllib.request.urlopen(  # noqa: S310
        request, timeout=timeout, context=context
    ) as response:
        status: int = response.status
        return status


def notify_failure(
    settings: Settings,
    *,
    command: str,
    exit_code: int,
    message: str,
    detail: str | None = None,
    dry_run: bool = False,
) -> WebhookResult:
    """Post a failure notification if one is configured. Never raises.

    Returns a ``WebhookResult`` describing what happened, so the CLI can surface delivery
    problems in ``--json`` output without letting them affect the process exit code.
    """
    if not settings.webhook_url:
        return WebhookResult.skipped("no webhook configured")
    if not settings.webhook_on_failure:
        return WebhookResult.skipped("webhook.on_failure is disabled")
    if exit_code in _SUCCESS_CODES:
        return WebhookResult.skipped(f"exit {exit_code} is a success outcome")
    if dry_run:
        # A dry run must not produce externally visible side effects, and an alert is one.
        return WebhookResult.skipped("dry-run: notification suppressed")

    try:
        url = validate_webhook_url(settings.webhook_url, allow_http=settings.webhook_allow_http)
    except WebhookConfigError as exc:
        return WebhookResult(attempted=False, delivered=False, reason=str(exc))

    token = os.environ.get(settings.webhook_token_env) if settings.webhook_token_env else None
    payload = build_payload(
        command=command,
        exit_code=exit_code,
        message=message,
        detail=detail,
        settings=settings,
        include_detail=settings.webhook_include_detail,
    )

    try:
        status = _post(url, payload, timeout=settings.webhook_timeout, token=token)
    except urllib.error.HTTPError as exc:
        return WebhookResult(
            attempted=True, delivered=False, status=exc.code, reason=f"HTTP {exc.code}"
        )
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        # Broad on purpose. Every transport failure mode — DNS, refused connection, TLS
        # handshake, timeout — must end here rather than propagate into an error path that
        # was already handling a different, more important failure.
        return WebhookResult(attempted=True, delivered=False, reason=f"{type(exc).__name__}: {exc}")

    delivered = 200 <= status < 300
    return WebhookResult(
        attempted=True,
        delivered=delivered,
        status=status,
        reason="" if delivered else f"unexpected status {status}",
    )
