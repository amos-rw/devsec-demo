"""
amos/tests.py  —  IDOR access-control tests for the view_profile endpoint.

Assignment: prevent-idor-profile-access
Security topic: Insecure Direct Object Reference (IDOR) / Broken Access Control

The view at /amos/profile/<pk>/ looks up a user profile by a predictable
integer identifier.  Without an explicit ownership check, any authenticated
user could read any other user's data by changing that number in the URL.

These tests verify that the object-level access control is correct:
  - Anonymous users  →  redirect to login (authentication gate)
  - Owner            →  200 OK  (authorised)
  - Regular user accessing someone else's profile  →  403 Forbidden  (IDOR blocked)
  - Instructor accessing any profile  →  200 OK  (role-based exception)
  - Non-existent pk  →  404 Not Found

Docs: https://docs.djangoproject.com/en/5.2/topics/testing/tools/
"""

from django.contrib.auth.models import Group, User
from django.test import TestCase
from django.urls import reverse


STRONG_PASSWORD = "Tr0ub4dor&3"


def make_user(username, password=STRONG_PASSWORD):
    return User.objects.create_user(username=username, password=password)


class ViewProfileIDORTests(TestCase):
    """
    Object-level access control for GET /amos/profile/<pk>/.

    The endpoint is vulnerable to IDOR if the only check is 'is the user
    logged in?'.  These tests confirm that identity alone is not sufficient —
    the user must also *own* the profile or hold the instructor role.
    """

    def setUp(self):
        self.group, _ = Group.objects.get_or_create(name="instructor")
        self.alice = make_user("alice")          # regular user
        self.bob = make_user("bob")              # another regular user
        self.instructor = make_user("prof")
        self.instructor.groups.add(self.group)

    def _url(self, user):
        return reverse("amos:view_profile", kwargs={"pk": user.pk})

    # ── Anonymous ──────────────────────────────────────────────────────────

    def test_anonymous_redirected_to_login(self):
        """Unauthenticated requests must be sent to the login page, not leak data."""
        response = self.client.get(self._url(self.alice))
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    # ── Owner access ───────────────────────────────────────────────────────

    def test_owner_can_view_own_profile(self):
        """A user must always be able to view their own profile."""
        self.client.force_login(self.alice)
        response = self.client.get(self._url(self.alice))
        self.assertEqual(response.status_code, 200)

    def test_own_profile_page_shows_correct_username(self):
        """The rendered page must display the owner's username."""
        self.client.force_login(self.alice)
        response = self.client.get(self._url(self.alice))
        self.assertContains(response, "alice")

    # ── IDOR: regular user cannot access another user's profile ────────────

    def test_user_cannot_view_another_users_profile(self):
        """
        IDOR check: alice is authenticated but must not reach bob's profile.
        Checking login state alone is not sufficient — ownership must be verified.
        """
        self.client.force_login(self.alice)
        response = self.client.get(self._url(self.bob))
        self.assertEqual(response.status_code, 403)

    def test_forbidden_response_does_not_reveal_profile_data(self):
        """The 403 page must not leak the target user's data."""
        self.client.force_login(self.alice)
        response = self.client.get(self._url(self.bob))
        self.assertNotContains(response, "bob", status_code=403)

    # ── Instructor role exception ──────────────────────────────────────────

    def test_instructor_can_view_any_profile(self):
        """Instructors are explicitly authorised to view all profiles."""
        self.client.force_login(self.instructor)
        response = self.client.get(self._url(self.alice))
        self.assertEqual(response.status_code, 200)

    def test_instructor_can_view_own_profile(self):
        """Instructors can also view their own profile via this endpoint."""
        self.client.force_login(self.instructor)
        response = self.client.get(self._url(self.instructor))
        self.assertEqual(response.status_code, 200)

    def test_instructor_sees_correct_username_on_profile(self):
        """The rendered page must display the viewed user's username, not the instructor's."""
        self.client.force_login(self.instructor)
        response = self.client.get(self._url(self.alice))
        self.assertContains(response, "alice")

    # ── Non-existent resource ──────────────────────────────────────────────

    def test_nonexistent_pk_returns_404_for_instructor(self):
        """
        An instructor requesting a pk that does not exist must get 404, not 500.
        get_object_or_404 must be used rather than a bare .get() call.
        """
        self.client.force_login(self.instructor)
        response = self.client.get(
            reverse("amos:view_profile", kwargs={"pk": 99999})
        )
        self.assertEqual(response.status_code, 404)

    def test_nonexistent_pk_returns_403_for_regular_user(self):
        """
        A regular user requesting a pk they don't own must receive 403 Forbidden,
        not 404 — this avoids leaking whether an account exists at that id.
        The access check fires before the database lookup.
        """
        self.client.force_login(self.alice)
        response = self.client.get(
            reverse("amos:view_profile", kwargs={"pk": 99999})
        )
        self.assertEqual(response.status_code, 403)

    # ── Role promotion / demotion affects access ───────────────────────────

    def test_promoting_user_grants_access_to_other_profiles(self):
        """Adding a user to the instructor group must immediately unlock other profiles."""
        self.client.force_login(self.alice)
        self.assertEqual(self.client.get(self._url(self.bob)).status_code, 403)
        self.alice.groups.add(self.group)
        self.assertEqual(self.client.get(self._url(self.bob)).status_code, 200)

    def test_demoting_instructor_revokes_access_to_other_profiles(self):
        """Removing a user from the instructor group must immediately re-block access."""
        self.client.force_login(self.instructor)
        self.assertEqual(self.client.get(self._url(self.alice)).status_code, 200)
        self.instructor.groups.remove(self.group)
        self.assertEqual(self.client.get(self._url(self.alice)).status_code, 403)
