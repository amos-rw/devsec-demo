"""
amos/tests.py  —  Django security-settings tests.

Assignment: harden-django-security-settings
Security topic: Security misconfiguration and unsafe production defaults.

What these tests verify
------------------------
  Settings correctness
  1. DEBUG is parsed as a real boolean, not a string.
  2. SECRET_KEY is set and non-empty.
  3. ALLOWED_HOSTS is non-empty (cannot be the empty list that rejects all requests).
  4. SESSION_COOKIE_HTTPONLY is True.
  5. SESSION_COOKIE_SAMESITE is 'Lax'.
  6. SECURE_CONTENT_TYPE_NOSNIFF is True.
  7. X_FRAME_OPTIONS is 'DENY'.
  8. SECURE_REFERRER_POLICY is set.

  HTTP response headers  (SecurityMiddleware and XFrameOptionsMiddleware)
  9.  X-Content-Type-Options: nosniff is present on responses.
  10. X-Frame-Options: DENY is present on responses.
  11. Referrer-Policy header is present on responses.

Why each setting matters
-------------------------
  DEBUG as boolean     A string 'False' is truthy in Python.
                       bool('False') == True — DEBUG appears off but stays on.
  SECRET_KEY           A missing key lets Django start with SECRET_KEY=None,
                       crashing unpredictably; a weak key lets attackers forge
                       signed cookies and session tokens.
  ALLOWED_HOSTS        An empty list with DEBUG=False rejects every request
                       with HTTP 400.
  SESSION_COOKIE_HTTPONLY  Prevents JavaScript from reading the session cookie
                       (mitigates cookie theft via XSS).
  SESSION_COOKIE_SAMESITE  Blocks the cookie in cross-site POST requests,
                       adding a browser-side CSRF defence layer.
  NOSNIFF              Stops browsers from MIME-sniffing a text file into an
                       executable HTML context.
  X-Frame-Options DENY Blocks clickjacking — a login form must never be
                       embeddable in an attacker's iframe.
  Referrer-Policy      Prevents internal paths from leaking to third-party
                       servers in the Referer header.

Docs: https://docs.djangoproject.com/en/5.2/topics/security/
      https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/
"""

from django.conf import settings
from django.test import TestCase
from django.urls import reverse


# ---------------------------------------------------------------------------
# Settings correctness tests
# ---------------------------------------------------------------------------

class SecuritySettingsTests(TestCase):
    """Verify that security-relevant settings have safe, deliberate values."""

    def test_debug_is_a_real_boolean(self):
        """
        DEBUG must be a Python bool, not a string.

        os.environ.get() returns a string.  bool('False') == True in Python
        because non-empty strings are truthy — a subtle bug that leaves debug
        mode on even when the operator intended to turn it off.  The _env_bool()
        helper in settings.py parses it correctly.
        """
        self.assertIsInstance(settings.DEBUG, bool,
            "DEBUG must be bool, not a string.  "
            "os.environ.get() returns a string; use _env_bool() to parse it.")

    def test_secret_key_is_set_and_non_empty(self):
        """SECRET_KEY must be a non-empty string."""
        self.assertIsNotNone(settings.SECRET_KEY,
            "SECRET_KEY must not be None.")
        self.assertIsInstance(settings.SECRET_KEY, str)
        self.assertGreater(len(settings.SECRET_KEY), 0,
            "SECRET_KEY must not be an empty string.")

    def test_allowed_hosts_is_not_empty(self):
        """
        ALLOWED_HOSTS must contain at least one entry.

        An empty list with DEBUG=False causes Django to return HTTP 400 for
        every request because no Host header can ever match.
        """
        self.assertGreater(len(settings.ALLOWED_HOSTS), 0,
            "ALLOWED_HOSTS must not be empty.")

    def test_session_cookie_httponly_is_true(self):
        """
        SESSION_COOKIE_HTTPONLY=True prevents JavaScript from reading the
        session cookie, limiting the impact of an XSS vulnerability.
        """
        self.assertTrue(settings.SESSION_COOKIE_HTTPONLY)

    def test_session_cookie_samesite_is_lax(self):
        """
        SESSION_COOKIE_SAMESITE='Lax' instructs the browser to omit the
        session cookie on cross-site POST requests, providing a browser-side
        CSRF defence on top of Django's token check.
        """
        self.assertEqual(settings.SESSION_COOKIE_SAMESITE, 'Lax')

    def test_secure_content_type_nosniff_is_true(self):
        """
        SECURE_CONTENT_TYPE_NOSNIFF=True causes SecurityMiddleware to add
        X-Content-Type-Options: nosniff, preventing browsers from guessing
        a different MIME type from the declared Content-Type.
        """
        self.assertTrue(settings.SECURE_CONTENT_TYPE_NOSNIFF)

    def test_x_frame_options_is_deny(self):
        """
        X_FRAME_OPTIONS='DENY' prevents this application from being embedded
        in an <iframe> on any origin.  A login service should never be
        frameable — framing enables clickjacking attacks.
        Django's XFrameOptionsMiddleware default is SAMEORIGIN, not DENY.
        """
        self.assertEqual(settings.X_FRAME_OPTIONS, 'DENY')

    def test_secure_referrer_policy_is_set(self):
        """
        SECURE_REFERRER_POLICY should be set so the SecurityMiddleware adds a
        Referrer-Policy header, preventing internal paths from leaking to
        external servers via the Referer header.
        """
        policy = getattr(settings, 'SECURE_REFERRER_POLICY', None)
        self.assertIsNotNone(policy,
            "SECURE_REFERRER_POLICY should be set.")
        self.assertNotEqual(policy, '',
            "SECURE_REFERRER_POLICY must not be an empty string.")


# ---------------------------------------------------------------------------
# HTTP response header tests
# ---------------------------------------------------------------------------

class SecurityHeadersTests(TestCase):
    """
    Verify that security headers are present in actual HTTP responses.

    Testing at the response level (not just the settings) confirms that
    the middleware is active and wired up correctly.
    """

    def _get_login(self):
        """Fetch the login page — a public endpoint that does not redirect."""
        return self.client.get(reverse('amos:login'))

    def test_x_content_type_options_header_present(self):
        """Every response must include X-Content-Type-Options: nosniff."""
        response = self._get_login()
        self.assertEqual(
            response.get('X-Content-Type-Options'), 'nosniff',
            "X-Content-Type-Options: nosniff header must be present."
        )

    def test_x_frame_options_header_is_deny(self):
        """Every response must include X-Frame-Options: DENY."""
        response = self._get_login()
        self.assertEqual(
            response.get('X-Frame-Options'), 'DENY',
            "X-Frame-Options: DENY header must be present."
        )

    def test_referrer_policy_header_present(self):
        """Every response must include a Referrer-Policy header."""
        response = self._get_login()
        self.assertIsNotNone(
            response.get('Referrer-Policy'),
            "Referrer-Policy header must be present in responses."
        )
