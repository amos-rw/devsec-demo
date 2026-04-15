"""
amos/audit.py — Security audit log helpers.

All security-relevant authentication events in this app are funnelled through
this module so that:

  * the logger name ("amos.audit") is a single configuration point in settings;
  * views stay focused on HTTP concerns and do not inline logging details;
  * it is easy to review exactly which events are tracked and what data they carry.

What is intentionally NEVER logged
------------------------------------
  * Raw passwords or password hashes — a log compromise must not leak credentials.
  * CSRF tokens or session keys — these are bearer credentials.
  * Full request bodies — these may contain any of the above.

The client IP is extracted on a best-effort basis.  If the app sits behind a
trusted reverse proxy, review HTTP_X_FORWARDED_FOR trust in your deployment.

Docs: https://docs.djangoproject.com/en/5.2/topics/logging/
"""

import logging

_log = logging.getLogger("amos.audit")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ip(request) -> str:
    """Best-effort client IP address."""
    xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
    return xff.split(",")[0].strip() if xff else request.META.get("REMOTE_ADDR", "-")


# ---------------------------------------------------------------------------
# Public audit events
# ---------------------------------------------------------------------------

def registration_succeeded(request, username: str) -> None:
    _log.info("event=registration.success username=%r ip=%s", username, _ip(request))


def login_succeeded(request, username: str) -> None:
    _log.info("event=login.success username=%r ip=%s", username, _ip(request))


def login_failed(request, username: str) -> None:
    _log.warning("event=login.failure username=%r ip=%s", username, _ip(request))


def login_locked(request, username: str) -> None:
    """Fired when a login request is blocked because the account is locked out."""
    _log.warning("event=login.locked username=%r ip=%s", username, _ip(request))


def logout_succeeded(request, username: str) -> None:
    _log.info("event=logout.success username=%r ip=%s", username, _ip(request))


def password_changed(request, username: str) -> None:
    _log.info("event=password_change.success username=%r ip=%s", username, _ip(request))


def password_reset_requested(request, email: str) -> None:
    """
    Log a password-reset request.

    The submitted email address is recorded for abuse detection.  This is
    server-side only and does not affect the anti-enumeration behaviour of
    the HTTP response — the same success page is shown whether or not the
    address is registered.
    """
    _log.info("event=password_reset.requested email=%r ip=%s", email, _ip(request))


def password_reset_completed(request, username: str) -> None:
    _log.info("event=password_reset.complete username=%r ip=%s", username, _ip(request))
