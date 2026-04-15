"""
amos/tests.py  —  Secure password reset workflow tests.

Assignment: secure-password-reset
Security topic: Token-based account recovery and user enumeration prevention.

Django's PasswordResetView generates a HMAC-SHA256 token that is:
  - Tied to the user's current password hash and last_login timestamp
  - Single-use: the token is invalidated as soon as the password changes
  - Time-limited: expires after PASSWORD_RESET_TIMEOUT seconds (1 hour here)

These tests verify the full reset flow and the security properties of each step.

Docs: https://docs.djangoproject.com/en/5.2/topics/auth/default/#django.contrib.auth.views.PasswordResetView
"""

from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.test import Client, TestCase
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode


STRONG_PASSWORD = "Tr0ub4dor&3"
NEW_PASSWORD    = "Fr3shP@ssw0rd!"


def make_user(username, password=STRONG_PASSWORD, email=""):
    return User.objects.create_user(username=username, password=password, email=email)


class PasswordResetFlowTests(TestCase):
    """
    End-to-end tests for the four-step password reset workflow:

      1. Request  — user submits their email address
      2. Done     — neutral confirmation page (anti-enumeration)
      3. Confirm  — user follows the token link and sets a new password
      4. Complete — success page with a link back to login

    Security properties verified:
      - Unknown email shows the same page as a known email (no enumeration)
      - Only a valid, unexpired token allows a password reset
      - The token is invalidated after one successful use
      - The new password must pass AUTH_PASSWORD_VALIDATORS
    """

    def setUp(self):
        # alice has a known email; used to test the happy path.
        self.user = make_user("alice", email="alice@example.com")

    def _confirm_url(self, user):
        """Build a valid reset-confirm URL for *user* using Django's token generator."""
        uid   = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        return reverse("amos:password_reset_confirm", kwargs={"uidb64": uid, "token": token})

    # ── Step 1: Request page ───────────────────────────────────────────────

    def test_request_page_loads(self):
        response = self.client.get(reverse("amos:password_reset"))
        self.assertEqual(response.status_code, 200)

    def test_known_email_sends_reset_email(self):
        """A registered email address must trigger one outgoing reset email."""
        self.client.post(reverse("amos:password_reset"), {"email": "alice@example.com"})
        self.assertEqual(len(mail.outbox), 1)

    def test_reset_email_contains_reset_link(self):
        """The email body must contain the password-reset path."""
        self.client.post(reverse("amos:password_reset"), {"email": "alice@example.com"})
        self.assertIn("password-reset", mail.outbox[0].body)

    def test_unknown_email_sends_no_email(self):
        """
        Anti-enumeration: submitting an unregistered address must not send
        an email.  Confirming absence of delivery prevents account discovery.
        """
        self.client.post(reverse("amos:password_reset"), {"email": "ghost@example.com"})
        self.assertEqual(len(mail.outbox), 0)

    def test_both_known_and_unknown_email_redirect_to_same_done_page(self):
        """
        Anti-enumeration: both paths must end at the same done URL so an
        attacker cannot tell from the response whether an address is registered.
        """
        known_resp   = self.client.post(reverse("amos:password_reset"), {"email": "alice@example.com"})
        unknown_resp = self.client.post(reverse("amos:password_reset"), {"email": "ghost@example.com"})
        done_url = reverse("amos:password_reset_done")
        self.assertRedirects(known_resp,   done_url)
        self.assertRedirects(unknown_resp, done_url)

    def test_login_page_has_forgot_password_link(self):
        """The login page must expose the reset entry point."""
        response = self.client.get(reverse("amos:login"))
        self.assertContains(response, reverse("amos:password_reset"))

    # ── Step 2: Done page ─────────────────────────────────────────────────

    def test_done_page_loads(self):
        response = self.client.get(reverse("amos:password_reset_done"))
        self.assertEqual(response.status_code, 200)

    # ── Step 3: Confirm page ──────────────────────────────────────────────

    def test_valid_token_confirm_page_loads(self):
        """Following a genuine token link must show the set-password form."""
        response = self.client.get(self._confirm_url(self.user), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["validlink"])

    def test_valid_token_can_set_new_password(self):
        """Submitting a strong password with a valid token must update the hash."""
        response = self.client.get(self._confirm_url(self.user), follow=True)
        self.client.post(response.wsgi_request.path, {
            "new_password1": NEW_PASSWORD,
            "new_password2": NEW_PASSWORD,
        })
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(NEW_PASSWORD))

    def test_valid_reset_redirects_to_complete_page(self):
        """A successful reset must redirect to the complete page."""
        response = self.client.get(self._confirm_url(self.user), follow=True)
        result = self.client.post(response.wsgi_request.path, {
            "new_password1": NEW_PASSWORD,
            "new_password2": NEW_PASSWORD,
        })
        self.assertRedirects(result, reverse("amos:password_reset_complete"))

    def test_weak_new_password_is_rejected(self):
        """
        AUTH_PASSWORD_VALIDATORS apply to the reset form just as they do at
        registration — a weak password must be rejected and the old one kept.
        """
        response = self.client.get(self._confirm_url(self.user), follow=True)
        self.client.post(response.wsgi_request.path, {
            "new_password1": "password123",
            "new_password2": "password123",
        })
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(STRONG_PASSWORD))

    def test_invalid_token_shows_invalid_link_page(self):
        """
        A tampered or expired token must render the template with
        validlink=False so the user sees a clear error, not a 500 page.
        """
        uid     = urlsafe_base64_encode(force_bytes(self.user.pk))
        bad_url = reverse("amos:password_reset_confirm",
                          kwargs={"uidb64": uid, "token": "bad-token-xyz"})
        response = self.client.get(bad_url, follow=True)
        self.assertFalse(response.context["validlink"])

    def test_token_is_single_use(self):
        """
        After a successful reset the user's password hash changes, which
        invalidates the original HMAC token.  A second attempt with the same
        link must be rejected — reset links cannot be replayed.
        """
        confirm_url = self._confirm_url(self.user)

        # First use: complete the reset successfully.
        response = self.client.get(confirm_url, follow=True)
        self.client.post(response.wsgi_request.path, {
            "new_password1": NEW_PASSWORD,
            "new_password2": NEW_PASSWORD,
        })

        # Second attempt: fresh client has no session carrying the old token,
        # so Django must re-validate the raw token — which is now invalid.
        second         = Client()
        second_response = second.get(confirm_url, follow=True)
        self.assertFalse(second_response.context["validlink"])

    # ── Step 4: Complete page ─────────────────────────────────────────────

    def test_complete_page_loads(self):
        response = self.client.get(reverse("amos:password_reset_complete"))
        self.assertEqual(response.status_code, 200)

    def test_complete_page_links_to_login(self):
        """The complete page must provide a direct path back to sign in."""
        response = self.client.get(reverse("amos:password_reset_complete"))
        self.assertContains(response, reverse("amos:login"))
