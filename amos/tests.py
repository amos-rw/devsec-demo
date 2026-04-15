"""
amos/tests.py  —  Audit logging tests for security-relevant auth events.

Assignment: add-auth-audit-logging
Security topic: Audit logging, accountability, and security event visibility.

Why audit logging matters
--------------------------
Prevention controls (password hashing, CSRF tokens, rate-limiting) stop most
attacks.  Audit logging answers the question "what happened after the fact?"
— it is essential for incident response, compliance, and detecting patterns
(e.g. slow-and-low brute force) that no single request triggers.

Events logged by this app
--------------------------
  registration.success   — a new account was created
  login.success          — a user authenticated successfully
  login.failure          — bad credentials were presented
  login.locked           — a request was rejected because the account is locked
  logout.success         — a user signed out
  password_change.success — a logged-in user changed their password
  password_reset.requested — a password-reset email was requested
  password_reset.complete  — a password was reset via a valid token

What is NEVER logged
---------------------
  Raw passwords, password hashes, CSRF tokens, and session keys must never
  appear in any log message.  The tests enforce this for the login path.

These tests verify that:

  1. Registration emits registration.success
  2. Successful login emits login.success
  3. Failed login emits login.failure
  4. A locked-out login attempt emits login.locked
  5. Logout emits logout.success
  6. Password change emits password_change.success
  7. A password-reset request emits password_reset.requested
  8. Raw passwords never appear in any audit log line

Docs: https://docs.djangoproject.com/en/5.2/topics/logging/#django-s-logging-extensions
"""

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse


STRONG_PASSWORD = "Tr0ub4dor&3"


class AuditLoggingTests(TestCase):
    """
    Each test uses assertLogs("amos.audit", ...) to capture records emitted
    by the amos.audit logger and assert the expected event keyword is present.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            "alice", email="alice@example.com", password=STRONG_PASSWORD
        )
        self.login_url = reverse("amos:login")

    # ── Helper ─────────────────────────────────────────────────────────────

    def _post_login(self, password=STRONG_PASSWORD):
        return self.client.post(
            self.login_url,
            {"username": "alice", "password": password},
        )

    # ── Registration ───────────────────────────────────────────────────────

    def test_registration_is_logged(self):
        """A new registration must emit registration.success."""
        with self.assertLogs("amos.audit", level="INFO") as cm:
            self.client.post(reverse("amos:register"), {
                "username": "bob",
                "email": "bob@example.com",
                "password1": STRONG_PASSWORD,
                "password2": STRONG_PASSWORD,
            })
        self.assertTrue(any("registration.success" in m for m in cm.output))

    # ── Login ──────────────────────────────────────────────────────────────

    def test_login_success_is_logged(self):
        """Successful authentication must emit login.success."""
        with self.assertLogs("amos.audit", level="INFO") as cm:
            self._post_login()
        self.assertTrue(any("login.success" in m for m in cm.output))

    def test_login_failure_is_logged(self):
        """A failed login attempt must emit login.failure."""
        with self.assertLogs("amos.audit", level="WARNING") as cm:
            self._post_login(password="wrongpassword")
        self.assertTrue(any("login.failure" in m for m in cm.output))

    def test_login_lockout_is_logged(self):
        """
        Once an account is locked, subsequent attempts must emit login.locked.
        Five failures trigger the lockout; the sixth request hits the guard.
        """
        with self.assertLogs("amos.audit", level="WARNING") as cm:
            for _ in range(6):
                self._post_login(password="wrongpassword")
        self.assertTrue(any("login.locked" in m for m in cm.output))

    # ── Logout ─────────────────────────────────────────────────────────────

    def test_logout_is_logged(self):
        """POST to logout must emit logout.success."""
        self.client.force_login(self.user)
        with self.assertLogs("amos.audit", level="INFO") as cm:
            self.client.post(reverse("amos:logout"))
        self.assertTrue(any("logout.success" in m for m in cm.output))

    # ── Password change ────────────────────────────────────────────────────

    def test_password_change_is_logged(self):
        """A successful in-session password change must emit password_change.success."""
        self.client.force_login(self.user)
        with self.assertLogs("amos.audit", level="INFO") as cm:
            self.client.post(reverse("amos:password_change"), {
                "old_password": STRONG_PASSWORD,
                "new_password1": "NewP@ssw0rd!",
                "new_password2": "NewP@ssw0rd!",
            })
        self.assertTrue(any("password_change.success" in m for m in cm.output))

    # ── Password reset ─────────────────────────────────────────────────────

    def test_password_reset_request_is_logged(self):
        """Submitting the password-reset form must emit password_reset.requested."""
        with self.assertLogs("amos.audit", level="INFO") as cm:
            self.client.post(reverse("amos:password_reset"), {
                "email": "alice@example.com",
            })
        self.assertTrue(any("password_reset.requested" in m for m in cm.output))

    # ── Privacy guard ──────────────────────────────────────────────────────

    def test_password_never_appears_in_logs(self):
        """
        Raw passwords must never be written to the audit log.
        A log file compromise must not expose user credentials.
        """
        with self.assertLogs("amos.audit", level="INFO") as cm:
            self._post_login()
        for line in cm.output:
            self.assertNotIn(STRONG_PASSWORD, line)
