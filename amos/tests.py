"""
amos/tests.py  —  Brute-force login protection tests.

Assignment: harden-login-bruteforce
Security topic: Authentication abuse, attempt tracking, account lockout.

Design under test:
  - After _MAX_ATTEMPTS (5) consecutive failures the account is locked for
    _LOCKOUT_DURATION (15 minutes).
  - The lockout is account-based (keyed on normalised username).
  - A successful login clears the attempt record entirely.
  - Once the lockout window expires the counter resets for a fresh window.

Docs: https://docs.djangoproject.com/en/5.2/topics/testing/tools/
"""

from datetime import timedelta

from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .models import LoginAttempt


STRONG_PASSWORD = "Tr0ub4dor&3"


def make_user(username, password=STRONG_PASSWORD):
    return User.objects.create_user(username=username, password=password)


class BruteForceProtectionTests(TestCase):
    """
    Tests for the brute-force login protection layer.

    Each test is independent — setUp creates a fresh user and the test
    database is rolled back between tests, so attempt records do not leak.
    """

    def setUp(self):
        self.user      = make_user("alice")
        self.login_url = reverse("amos:login")

    def _fail(self, username="alice", n=1):
        """Submit n failed login attempts for *username*."""
        for _ in range(n):
            self.client.post(self.login_url, {
                "username": username,
                "password": "definitely-wrong",
            })

    # ── Normal login (regression guard) ───────────────────────────────────

    def test_correct_credentials_still_log_in(self):
        """The happy path must not be broken by the protection layer."""
        response = self.client.post(self.login_url, {
            "username": "alice",
            "password": STRONG_PASSWORD,
        })
        self.assertRedirects(response, reverse("amos:dashboard"))

    def test_correct_credentials_authenticate_user(self):
        response = self.client.post(self.login_url, {
            "username": "alice",
            "password": STRONG_PASSWORD,
        }, follow=True)
        self.assertTrue(response.context["user"].is_authenticated)

    # ── Attempt counter ────────────────────────────────────────────────────

    def test_single_failure_does_not_lock(self):
        """One wrong password must not trigger a lockout."""
        self._fail(n=1)
        attempt = LoginAttempt.objects.get(username="alice")
        self.assertIsNone(attempt.locked_until)

    def test_four_failures_do_not_lock(self):
        """Four failures (one under the threshold) must not lock the account."""
        self._fail(n=4)
        attempt = LoginAttempt.objects.get(username="alice")
        self.assertIsNone(attempt.locked_until)

    def test_five_failures_trigger_lockout(self):
        """The fifth consecutive failure must set a lockout timestamp."""
        self._fail(n=5)
        attempt = LoginAttempt.objects.get(username="alice")
        self.assertIsNotNone(attempt.locked_until)
        self.assertGreater(attempt.locked_until, timezone.now())

    def test_failure_count_increments_correctly(self):
        self._fail(n=3)
        self.assertEqual(LoginAttempt.objects.get(username="alice").failed_count, 3)

    # ── Lockout enforcement ────────────────────────────────────────────────

    def test_locked_account_rejects_correct_password(self):
        """
        Core IDOR check: even the correct password must be blocked during
        a lockout window so credential stuffing cannot succeed.
        """
        LoginAttempt.objects.create(
            username="alice",
            failed_count=5,
            locked_until=timezone.now() + timedelta(minutes=10),
        )
        response = self.client.post(self.login_url, {
            "username": "alice",
            "password": STRONG_PASSWORD,
        }, follow=True)
        self.assertFalse(response.context["user"].is_authenticated)

    def test_locked_account_returns_200_not_redirect(self):
        """A locked login attempt must re-render the page, not redirect."""
        LoginAttempt.objects.create(
            username="alice",
            failed_count=5,
            locked_until=timezone.now() + timedelta(minutes=10),
        )
        response = self.client.post(self.login_url, {
            "username": "alice",
            "password": STRONG_PASSWORD,
        })
        self.assertEqual(response.status_code, 200)

    def test_lockout_message_mentions_wait_time(self):
        """The error message must tell the user how long to wait."""
        LoginAttempt.objects.create(
            username="alice",
            failed_count=5,
            locked_until=timezone.now() + timedelta(minutes=10),
        )
        response = self.client.post(self.login_url, {
            "username": "alice",
            "password": STRONG_PASSWORD,
        })
        msg_texts = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertTrue(any("minute" in t for t in msg_texts))

    # ── Username normalisation ─────────────────────────────────────────────

    def test_username_tracking_is_case_insensitive(self):
        """
        Attempts with 'Alice' and 'alice' must count against the same record
        so an attacker cannot bypass the counter by alternating case.
        """
        self._fail(username="Alice", n=3)
        self._fail(username="ALICE", n=2)
        attempt = LoginAttempt.objects.get(username="alice")
        self.assertEqual(attempt.failed_count, 5)
        self.assertIsNotNone(attempt.locked_until)

    # ── Recovery ──────────────────────────────────────────────────────────

    def test_successful_login_clears_attempt_record(self):
        """After a successful login the attempt record must be deleted."""
        LoginAttempt.objects.create(username="alice", failed_count=3)
        self.client.post(self.login_url, {
            "username": "alice",
            "password": STRONG_PASSWORD,
        })
        self.assertFalse(LoginAttempt.objects.filter(username="alice").exists())

    def test_lockout_expiry_allows_login(self):
        """
        Once the lockout window has elapsed the account must accept valid
        credentials again — no admin intervention required.
        """
        LoginAttempt.objects.create(
            username="alice",
            failed_count=5,
            # Expired 1 second ago.
            locked_until=timezone.now() - timedelta(seconds=1),
        )
        response = self.client.post(self.login_url, {
            "username": "alice",
            "password": STRONG_PASSWORD,
        })
        self.assertRedirects(response, reverse("amos:dashboard"))

    def test_lockout_expiry_resets_counter(self):
        """After expiry the counter must restart from zero, not carry forward."""
        LoginAttempt.objects.create(
            username="alice",
            failed_count=5,
            locked_until=timezone.now() - timedelta(seconds=1),
        )
        # One failure after expiry must not immediately re-lock.
        self._fail(n=1)
        attempt = LoginAttempt.objects.get(username="alice")
        self.assertIsNone(attempt.locked_until)
        self.assertEqual(attempt.failed_count, 1)

    # ── Isolation between accounts ─────────────────────────────────────────

    def test_failures_on_one_account_do_not_affect_another(self):
        """Lockout records are scoped per username — other accounts are unaffected."""
        make_user("bob")
        self._fail(username="alice", n=5)
        # Bob's account must still accept correct credentials.
        response = self.client.post(self.login_url, {
            "username": "bob",
            "password": STRONG_PASSWORD,
        })
        self.assertRedirects(response, reverse("amos:dashboard"))
