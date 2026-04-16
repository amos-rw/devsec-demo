"""
amos/tests.py  —  Stored XSS tests for user-controlled profile content.

Assignment: fix-stored-xss-profile-content
Security topic: Stored cross-site scripting (XSS) in user bios.

Why stored XSS matters
-----------------------
Unlike reflected XSS (which requires tricking a user into clicking a crafted
URL), stored XSS persists in the database and fires automatically whenever
anyone views the affected page.  A single attacker who can write a malicious
bio poisons every future viewer — including administrators.

Typical attack payloads
-----------------------
  <script>...</script>          — executes arbitrary JavaScript
  <img src=x onerror=alert(1)> — fires JS via an event handler attribute
  <svg onload=fetch(...)>       — exfiltrates session cookies or CSRF tokens

The defence
-----------
Django's template engine escapes five special characters by default:
  <  →  &lt;    >  →  &gt;    "  →  &quot;    '  →  &#x27;    &  →  &amp;

As long as no {{ var|safe }} or {% autoescape off %} is present, stored
content can never break out of a text node into executable markup.

What these tests verify
-----------------------
  1. A stored <script> tag in a bio is entity-escaped, not executed.
  2. An <img onerror=…> payload is entity-escaped.
  3. Plain text in a bio renders normally (no over-escaping).
  4. Self-XSS: the payload is escaped even on the owner's own profile view.

Docs: https://docs.djangoproject.com/en/5.2/ref/templates/language/#automatic-html-escaping
"""

from django.contrib.auth.models import Group, User
from django.test import TestCase
from django.urls import reverse

from .models import Profile


class StoredXSSProfileTests(TestCase):
    """
    Each test writes a potentially malicious bio directly into the database
    (simulating a stored payload), then fetches the view_profile page and
    inspects the raw HTML for escaped vs. unescaped content.
    """

    def setUp(self):
        # alice: user whose bio carries the payload
        self.alice = User.objects.create_user(
            "alice", email="alice@example.com", password="Tr0ub4dor&3"
        )
        Profile.objects.get_or_create(user=self.alice)

        # bob: instructor who can view any profile (bypasses IDOR ownership check)
        self.bob = User.objects.create_user(
            "bob", email="bob@example.com", password="Tr0ub4dor&3"
        )
        instructor_group, _ = Group.objects.get_or_create(name="instructor")
        self.bob.groups.add(instructor_group)

    # ── Helper ─────────────────────────────────────────────────────────────

    def _set_bio(self, user, bio: str) -> None:
        """Write bio directly to the database — no HTTP round-trip."""
        profile, _ = Profile.objects.get_or_create(user=user)
        profile.bio = bio
        profile.save()

    def _get_profile_page(self, viewer, target_pk: int):
        self.client.force_login(viewer)
        return self.client.get(
            reverse("amos:view_profile", kwargs={"pk": target_pk})
        )

    # ── Script-tag payload ─────────────────────────────────────────────────

    def test_script_tag_in_bio_is_escaped(self):
        """
        A stored <script> payload must appear entity-escaped in the HTML, not
        as a live script element that the browser would execute.
        """
        self._set_bio(self.alice, "<script>alert('xss')</script>")
        response = self._get_profile_page(self.bob, self.alice.pk)

        self.assertEqual(response.status_code, 200)
        content = response.content.decode()

        # Raw tag must not appear anywhere in the page.
        self.assertNotIn("<script>alert('xss')</script>", content)
        # Escaped version must be present (proves it was rendered, not silently dropped).
        self.assertIn("&lt;script&gt;", content)

    # ── Event-handler payload ──────────────────────────────────────────────

    def test_img_onerror_in_bio_is_escaped(self):
        """
        An <img onerror=…> payload must be escaped so the attribute cannot
        trigger JavaScript execution.
        """
        self._set_bio(self.alice, '<img src=x onerror=alert(1)>')
        response = self._get_profile_page(self.bob, self.alice.pk)

        content = response.content.decode()

        # Raw payload must not appear in the markup.
        self.assertNotIn('<img src=x onerror=alert(1)>', content)
        # Opening angle bracket of the tag must be escaped.
        self.assertIn("&lt;img", content)

    # ── Normal bio text ────────────────────────────────────────────────────

    def test_safe_bio_text_renders_correctly(self):
        """
        Plain text in the bio must appear unchanged so legitimate users are
        not affected by the escaping defence.
        """
        self._set_bio(self.alice, "I love Python and security!")
        response = self._get_profile_page(self.bob, self.alice.pk)
        self.assertContains(response, "I love Python and security!")

    # ── Self-XSS ───────────────────────────────────────────────────────────

    def test_own_profile_xss_payload_is_escaped(self):
        """
        Even viewing your own profile, a stored payload must be escaped.
        Self-XSS can be chained with other techniques, so it is not exempt.
        """
        self._set_bio(self.alice, "<script>document.cookie='stolen'</script>")
        # alice views her own profile — no IDOR restriction applies.
        response = self._get_profile_page(self.alice, self.alice.pk)

        content = response.content.decode()
        # The exact payload must not appear unescaped.  We test the specific
        # payload string rather than any <script> tag because the page
        # legitimately includes <script> blocks from the base template.
        self.assertNotIn("<script>document.cookie=", content)
        self.assertIn("&lt;script&gt;", content)
