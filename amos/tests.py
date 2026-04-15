"""
amos/tests.py  —  Open-redirect protection tests for the login flow.

Assignment: fix-open-redirects
Security topic: Open redirect vulnerabilities in authentication flows.

The endpoint under test is POST /amos/login/ (the ?next= redirect parameter).

Open-redirect risk
------------------
The login view accepts a ?next= query-string parameter so the user lands on
the page they originally requested after authenticating.  Without validating
that redirect target, an attacker crafts a link like:

    https://uas.example/amos/login/?next=http://evil.com/

The user authenticates on the legitimate site, sees the real domain in their
address bar, and is silently forwarded to a phishing page.  Because they just
"logged in" they trust the destination completely.

Fix applied
-----------
Every next= value is passed through Django's url_has_allowed_host_and_scheme()
utility before following it.  That helper rejects:

  • absolute URLs with a foreign host  (http://evil.com/…)
  • protocol-relative URLs             (//evil.com/…)
  • javascript: and data: URI schemes
  • any URL whose netloc differs from request.get_host()

Safe relative paths (e.g. /amos/profile/) are accepted unchanged.  When the
value is absent or rejected the view falls back to the dashboard.

These tests verify that:

  1. A valid internal next= URL is followed after login
  2. An absolute HTTP external URL is rejected; user lands on dashboard
  3. An absolute HTTPS external URL is also rejected
  4. A protocol-relative URL (//evil.com/) is rejected
  5. A javascript: scheme URI is rejected
  6. A data: scheme URI is rejected
  7. No next= parameter → dashboard (safe default)
  8. The GET login page renders the next= value so the form can forward it

Docs: https://docs.djangoproject.com/en/5.2/ref/utils/#django.utils.http.url_has_allowed_host_and_scheme
"""

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse


STRONG_PASSWORD = "Tr0ub4dor&3"


def make_user(username, password=STRONG_PASSWORD):
    return User.objects.create_user(username=username, password=password)


class OpenRedirectLoginTests(TestCase):
    """
    Open-redirect protection tests for the login view.

    All tests POST valid credentials; the only variable is the next=
    redirect target — safe, malicious, or absent.
    """

    def setUp(self):
        self.user         = make_user("alice")
        self.login_url    = reverse("amos:login")
        self.dashboard_url = reverse("amos:dashboard")

    # ── Helper ─────────────────────────────────────────────────────────────

    def _login(self, next_url=None):
        """POST valid credentials with an optional next= value."""
        data = {"username": "alice", "password": STRONG_PASSWORD}
        if next_url is not None:
            data["next"] = next_url
        return self.client.post(self.login_url, data)

    # ── Safe redirects ─────────────────────────────────────────────────────

    def test_no_next_redirects_to_dashboard(self):
        """No next= present → the user always lands on the dashboard."""
        response = self._login()
        self.assertRedirects(
            response, self.dashboard_url, fetch_redirect_response=False
        )

    def test_safe_internal_next_is_followed(self):
        """A next= pointing to a same-origin path must be followed."""
        response = self._login(next_url="/amos/profile/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/amos/profile/")

    # ── Unsafe redirects must be rejected ──────────────────────────────────

    def test_absolute_external_http_next_is_rejected(self):
        """
        http://evil.com/… must not be followed.
        url_has_allowed_host_and_scheme rejects any URL whose netloc differs
        from request.get_host(); the view falls back to the dashboard.
        """
        response = self._login(next_url="http://evil.com/steal")
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("evil.com", response["Location"])
        self.assertEqual(response["Location"], self.dashboard_url)

    def test_absolute_external_https_next_is_rejected(self):
        """HTTPS does not make a foreign host trustworthy."""
        response = self._login(next_url="https://attacker.example/phish")
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("attacker.example", response["Location"])
        self.assertEqual(response["Location"], self.dashboard_url)

    def test_protocol_relative_next_is_rejected(self):
        """
        //evil.com/path is treated as https://evil.com/path by browsers.
        It looks like a relative URL but carries a foreign host — must be
        rejected.
        """
        response = self._login(next_url="//evil.com/steal")
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("evil.com", response["Location"])
        self.assertEqual(response["Location"], self.dashboard_url)

    def test_javascript_scheme_next_is_rejected(self):
        """javascript: URIs can execute arbitrary code in some redirect contexts."""
        response = self._login(next_url="javascript:alert(document.cookie)")
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("javascript:", response["Location"])
        self.assertEqual(response["Location"], self.dashboard_url)

    def test_data_scheme_next_is_rejected(self):
        """data: URIs can embed HTML/JavaScript payloads."""
        response = self._login(
            next_url="data:text/html,<script>alert(1)</script>"
        )
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("data:", response["Location"])
        self.assertEqual(response["Location"], self.dashboard_url)

    # ── GET parameter forwarding ───────────────────────────────────────────

    def test_get_login_page_includes_next_in_response(self):
        """
        When the login page is loaded with ?next=, the value must appear in
        the rendered HTML (as a hidden form input) so the subsequent POST
        carries it forward to the redirect check.
        """
        response = self.client.get(f"{self.login_url}?next=/amos/profile/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "/amos/profile/")
