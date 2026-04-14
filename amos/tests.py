"""
amos/tests.py

Test suite for the amos User Authentication Service.

Django's test client handles sessions and cookies automatically, making it
ideal for testing full authentication flows end-to-end without a browser.

Docs: https://docs.djangoproject.com/en/5.2/topics/testing/tools/#the-test-client
"""

from django.contrib.auth.models import Group, User
from django.test import TestCase
from django.urls import reverse


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

# Passes all four AUTH_PASSWORD_VALIDATORS (length, common, numeric, similarity)
STRONG_PASSWORD = "Tr0ub4dor&3"

# Django's PBKDF2 password hasher is fully Unicode-aware (since Django 1.10).
# Using a non-ASCII password here proves the full auth pipeline handles
# characters outside the ASCII range correctly — important for international users.
# Docs: https://docs.djangoproject.com/en/5.2/topics/auth/passwords/
UNICODE_PASSWORD = "Sécur1té!日本語"


def make_user(username="amos", password=STRONG_PASSWORD):
    """Creates a User and returns it. Keeps setUp methods concise."""
    return User.objects.create_user(username=username, password=password)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

class RegistrationViewTests(TestCase):
    """Tests for GET and POST /amos/register/"""

    def test_register_page_loads(self):
        response = self.client.get(reverse("amos:register"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "<form")

    def test_successful_registration_creates_user(self):
        self.client.post(reverse("amos:register"), {
            "username": "amos",
            "email": "amos@example.com",
            "password1": STRONG_PASSWORD,
            "password2": STRONG_PASSWORD,
        })
        self.assertTrue(User.objects.filter(username="amos").exists())

    def test_successful_registration_creates_profile_via_signal(self):
        """The post_save signal must create a Profile for every new user."""
        self.client.post(reverse("amos:register"), {
            "username": "amos",
            "email": "amos@example.com",
            "password1": STRONG_PASSWORD,
            "password2": STRONG_PASSWORD,
        })
        user = User.objects.get(username="amos")
        self.assertTrue(hasattr(user, "profile"))

    def test_successful_registration_logs_user_in(self):
        """User should be authenticated immediately after registering."""
        response = self.client.post(reverse("amos:register"), {
            "username": "amos",
            "email": "amos@example.com",
            "password1": STRONG_PASSWORD,
            "password2": STRONG_PASSWORD,
        }, follow=True)
        self.assertTrue(response.context["user"].is_authenticated)

    def test_successful_registration_redirects_to_dashboard(self):
        response = self.client.post(reverse("amos:register"), {
            "username": "amos",
            "email": "amos@example.com",
            "password1": STRONG_PASSWORD,
            "password2": STRONG_PASSWORD,
        })
        self.assertRedirects(response, reverse("amos:dashboard"))

    def test_mismatched_passwords_rejected(self):
        response = self.client.post(reverse("amos:register"), {
            "username": "amos",
            "email": "amos@example.com",
            "password1": STRONG_PASSWORD,
            "password2": "totallydifferent99!",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username="amos").exists())

    def test_too_short_password_rejected(self):
        """MinimumLengthValidator (default: 8 chars) must block short passwords."""
        response = self.client.post(reverse("amos:register"), {
            "username": "amos",
            "email": "amos@example.com",
            "password1": "Ab1!",
            "password2": "Ab1!",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username="amos").exists())

    def test_common_password_rejected(self):
        """
        CommonPasswordValidator blocks passwords from the 20,000 most-used
        list — 'password123' is on it.
        Docs: https://docs.djangoproject.com/en/5.2/ref/password_validation/#django.contrib.auth.password_validation.CommonPasswordValidator
        """
        response = self.client.post(reverse("amos:register"), {
            "username": "amos",
            "email": "amos@example.com",
            "password1": "password123",
            "password2": "password123",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username="amos").exists())

    def test_numeric_only_password_rejected(self):
        """
        NumericPasswordValidator blocks passwords that are entirely digits.
        Docs: https://docs.djangoproject.com/en/5.2/ref/password_validation/#django.contrib.auth.password_validation.NumericPasswordValidator
        """
        response = self.client.post(reverse("amos:register"), {
            "username": "amos",
            "email": "amos@example.com",
            "password1": "87654321",
            "password2": "87654321",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username="amos").exists())

    def test_unicode_password_accepted(self):
        """
        Django's PBKDF2 hasher is Unicode-aware — passwords with non-ASCII
        characters (accented letters, CJK, Arabic, etc.) must be accepted.
        Docs: https://docs.djangoproject.com/en/5.2/topics/auth/passwords/
        """
        response = self.client.post(reverse("amos:register"), {
            "username": "amos",
            "email": "amos@example.com",
            "password1": UNICODE_PASSWORD,
            "password2": UNICODE_PASSWORD,
        })
        self.assertRedirects(response, reverse("amos:dashboard"))
        self.assertTrue(User.objects.filter(username="amos").exists())

    def test_duplicate_username_rejected(self):
        make_user("amos")
        response = self.client.post(reverse("amos:register"), {
            "username": "amos",
            "email": "other@example.com",
            "password1": STRONG_PASSWORD,
            "password2": STRONG_PASSWORD,
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(User.objects.filter(username="amos").count(), 1)

    def test_authenticated_user_redirected_away_from_register(self):
        self.client.force_login(make_user())
        response = self.client.get(reverse("amos:register"))
        self.assertRedirects(response, reverse("amos:dashboard"))


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

class LoginViewTests(TestCase):
    """Tests for GET and POST /amos/login/"""

    def setUp(self):
        self.user = make_user()

    def test_login_page_loads(self):
        response = self.client.get(reverse("amos:login"))
        self.assertEqual(response.status_code, 200)

    def test_valid_credentials_log_user_in(self):
        response = self.client.post(reverse("amos:login"), {
            "username": "amos",
            "password": STRONG_PASSWORD,
        }, follow=True)
        self.assertTrue(response.context["user"].is_authenticated)

    def test_valid_credentials_redirect_to_dashboard(self):
        response = self.client.post(reverse("amos:login"), {
            "username": "amos",
            "password": STRONG_PASSWORD,
        })
        self.assertRedirects(response, reverse("amos:dashboard"))

    def test_wrong_password_rejected(self):
        response = self.client.post(reverse("amos:login"), {
            "username": "amos",
            "password": "wrongpassword",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_nonexistent_user_rejected(self):
        response = self.client.post(reverse("amos:login"), {
            "username": "nobody",
            "password": STRONG_PASSWORD,
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_error_message_does_not_leak_username_existence(self):
        """
        Django's AuthenticationForm returns the same generic error whether
        the username does not exist or the password is wrong. This prevents
        user enumeration — an attacker cannot probe which usernames are taken.
        Docs: https://docs.djangoproject.com/en/5.2/topics/auth/default/#django.contrib.auth.forms.AuthenticationForm
        """
        # Wrong password for a real user.
        response_real = self.client.post(reverse("amos:login"), {
            "username": "amos",
            "password": "badpassword",
        })
        # Nonexistent user entirely.
        response_fake = self.client.post(reverse("amos:login"), {
            "username": "ghost_user_xyz",
            "password": "badpassword",
        })
        # Both should show the same non-field error text.
        self.assertEqual(
            response_real.context["form"].non_field_errors(),
            response_fake.context["form"].non_field_errors(),
        )

    def test_unicode_password_login(self):
        """A user registered with a Unicode password must be able to log back in."""
        User.objects.create_user(username="unicode_user", password=UNICODE_PASSWORD)
        response = self.client.post(reverse("amos:login"), {
            "username": "unicode_user",
            "password": UNICODE_PASSWORD,
        })
        self.assertRedirects(response, reverse("amos:dashboard"))

    def test_safe_next_redirect_is_followed(self):
        """A valid same-host ?next= value must be honoured after login."""
        next_url = reverse("amos:profile")
        response = self.client.post(
            f"{reverse('amos:login')}?next={next_url}",
            {"username": "amos", "password": STRONG_PASSWORD},
        )
        self.assertRedirects(response, next_url)

    def test_external_next_redirect_is_blocked(self):
        """
        Open-redirect guard: an attacker could craft a link like
        /amos/login/?next=https://evil.com to redirect a victim after login.
        url_has_allowed_host_and_scheme must block this.
        Docs: https://docs.djangoproject.com/en/5.2/ref/utils/#django.utils.http.url_has_allowed_host_and_scheme
        """
        response = self.client.post(
            f"{reverse('amos:login')}?next=https://evil.example.com",
            {"username": "amos", "password": STRONG_PASSWORD},
        )
        self.assertRedirects(response, reverse("amos:dashboard"))

    def test_authenticated_user_redirected_away_from_login(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("amos:login"))
        self.assertRedirects(response, reverse("amos:dashboard"))


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

class LogoutViewTests(TestCase):
    """Tests for GET and POST /amos/logout/"""

    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)

    def test_get_shows_confirmation_page(self):
        """GET must show a confirm page — not log the user out immediately."""
        response = self.client.get(reverse("amos:logout"))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.wsgi_request.user.is_authenticated)

    def test_post_logs_user_out(self):
        response = self.client.post(reverse("amos:logout"))
        self.assertRedirects(response, reverse("amos:login"))

    def test_after_logout_protected_pages_redirect(self):
        self.client.post(reverse("amos:logout"))
        response = self.client.get(reverse("amos:dashboard"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)


# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------

class AccessControlTests(TestCase):
    """Unauthenticated requests to protected URLs must redirect to login."""

    def test_dashboard_requires_login(self):
        response = self.client.get(reverse("amos:dashboard"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    def test_profile_requires_login(self):
        response = self.client.get(reverse("amos:profile"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    def test_password_change_requires_login(self):
        response = self.client.get(reverse("amos:password_change"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    def test_logout_requires_login(self):
        response = self.client.get(reverse("amos:logout"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    def test_dashboard_accessible_when_authenticated(self):
        self.client.force_login(make_user())
        response = self.client.get(reverse("amos:dashboard"))
        self.assertEqual(response.status_code, 200)


# ---------------------------------------------------------------------------
# Password change
# ---------------------------------------------------------------------------

class PasswordChangeTests(TestCase):
    """Tests for GET and POST /amos/password-change/"""

    NEW_PASSWORD = "N3wStr0ngP@ss!"

    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)

    def test_password_change_page_loads(self):
        response = self.client.get(reverse("amos:password_change"))
        self.assertEqual(response.status_code, 200)

    def test_successful_password_change_updates_hash(self):
        self.client.post(reverse("amos:password_change"), {
            "old_password": STRONG_PASSWORD,
            "new_password1": self.NEW_PASSWORD,
            "new_password2": self.NEW_PASSWORD,
        })
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.NEW_PASSWORD))

    def test_session_remains_valid_after_password_change(self):
        """
        update_session_auth_hash must keep the current session alive so the
        user is not signed out on the device they changed the password from.
        Docs: https://docs.djangoproject.com/en/5.2/topics/auth/default/#django.contrib.auth.update_session_auth_hash
        """
        self.client.post(reverse("amos:password_change"), {
            "old_password": STRONG_PASSWORD,
            "new_password1": self.NEW_PASSWORD,
            "new_password2": self.NEW_PASSWORD,
        })
        response = self.client.get(reverse("amos:dashboard"))
        self.assertEqual(response.status_code, 200)

    def test_wrong_old_password_rejected(self):
        response = self.client.post(reverse("amos:password_change"), {
            "old_password": "completely_wrong",
            "new_password1": self.NEW_PASSWORD,
            "new_password2": self.NEW_PASSWORD,
        })
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        # Original password must be unchanged.
        self.assertTrue(self.user.check_password(STRONG_PASSWORD))

    def test_new_password_must_pass_validators(self):
        """
        The new password goes through the same AUTH_PASSWORD_VALIDATORS as
        registration — a weak new password must be rejected.
        """
        response = self.client.post(reverse("amos:password_change"), {
            "old_password": STRONG_PASSWORD,
            "new_password1": "12345678",
            "new_password2": "12345678",
        })
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(STRONG_PASSWORD))

    def test_successful_password_change_redirects_to_dashboard(self):
        response = self.client.post(reverse("amos:password_change"), {
            "old_password": STRONG_PASSWORD,
            "new_password1": self.NEW_PASSWORD,
            "new_password2": self.NEW_PASSWORD,
        })
        self.assertRedirects(response, reverse("amos:dashboard"))

    def test_unicode_new_password_accepted(self):
        """New passwords with Unicode characters must be accepted and work on next login."""
        self.client.post(reverse("amos:password_change"), {
            "old_password": STRONG_PASSWORD,
            "new_password1": UNICODE_PASSWORD,
            "new_password2": UNICODE_PASSWORD,
        })
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(UNICODE_PASSWORD))


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------

class ProfileViewTests(TestCase):
    """Tests for GET and POST /amos/profile/"""

    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)

    def test_profile_page_loads(self):
        response = self.client.get(reverse("amos:profile"))
        self.assertEqual(response.status_code, 200)

    def test_bio_can_be_updated(self):
        self.client.post(reverse("amos:profile"), {"bio": "Hello, I am Amos."})
        self.user.profile.refresh_from_db()
        self.assertEqual(self.user.profile.bio, "Hello, I am Amos.")

    def test_empty_bio_is_valid(self):
        """bio is blank=True on the model — an empty string must be accepted."""
        response = self.client.post(reverse("amos:profile"), {"bio": ""})
        self.assertRedirects(response, reverse("amos:profile"))

    def test_bio_too_long_is_rejected(self):
        """max_length=500 on the model field must be enforced by the form."""
        response = self.client.post(reverse("amos:profile"), {"bio": "x" * 501})
        self.assertEqual(response.status_code, 200)
        self.user.profile.refresh_from_db()
        self.assertNotEqual(len(self.user.profile.bio), 501)

    def test_profile_created_automatically_for_admin_created_users(self):
        """
        The post_save signal creates a Profile for any User, even those
        created outside the registration form (e.g. management commands,
        fixtures, or the Django admin).
        """
        admin_user = User.objects.create_user(username="admin_test", password=STRONG_PASSWORD)
        response = self.client.get(reverse("amos:profile"))
        # Our own user's profile must exist — get_or_create handles the fallback.
        self.assertTrue(hasattr(self.user, "profile"))
        # The admin-created user also gets a profile via signal.
        self.assertTrue(hasattr(admin_user, "profile"))


# ---------------------------------------------------------------------------
# Role-based access control
# ---------------------------------------------------------------------------

class RBACTests(TestCase):
    """Authorization across the three tiers: anonymous, authenticated user, instructor.

    Each tier's allowed and denied paths are both covered so regressions in
    either direction (granting too much or too little) are caught.

    Docs: https://docs.djangoproject.com/en/5.2/topics/auth/default/#groups
    Docs: https://docs.djangoproject.com/en/5.2/topics/auth/default/#permissions-and-authorization
    """

    def setUp(self):
        self.group, _ = Group.objects.get_or_create(name="instructor")
        self.user = make_user("student")
        self.instructor = make_user("prof")
        self.instructor.groups.add(self.group)

    # ── Tier 1: Anonymous ──────────────────────────────────────────────────

    def test_anonymous_redirected_from_roster(self):
        """login_required fires before the group check — anonymous gets a login redirect."""
        response = self.client.get(reverse("amos:roster"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    def test_anonymous_redirected_from_dashboard(self):
        response = self.client.get(reverse("amos:dashboard"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("login", response.url)

    # ── Tier 2: Authenticated regular user ────────────────────────────────

    def test_regular_user_denied_roster(self):
        """Authenticated users outside the instructor group receive 403 Forbidden."""
        self.client.force_login(self.user)
        response = self.client.get(reverse("amos:roster"))
        self.assertEqual(response.status_code, 403)

    def test_regular_user_can_access_dashboard(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(reverse("amos:dashboard")).status_code, 200)

    def test_regular_user_can_access_profile(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(reverse("amos:profile")).status_code, 200)

    def test_regular_user_can_change_password(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(reverse("amos:password_change")).status_code, 200)

    def test_roster_link_hidden_from_regular_user(self):
        """The sidebar must not expose the roster URL to non-instructors."""
        self.client.force_login(self.user)
        response = self.client.get(reverse("amos:dashboard"))
        self.assertNotContains(response, reverse("amos:roster"))

    # ── Tier 3: Instructor ─────────────────────────────────────────────────

    def test_instructor_can_access_roster(self):
        self.client.force_login(self.instructor)
        self.assertEqual(self.client.get(reverse("amos:roster")).status_code, 200)

    def test_instructor_can_access_dashboard(self):
        self.client.force_login(self.instructor)
        self.assertEqual(self.client.get(reverse("amos:dashboard")).status_code, 200)

    def test_roster_lists_all_users(self):
        """The roster must include every registered account."""
        self.client.force_login(self.instructor)
        response = self.client.get(reverse("amos:roster"))
        self.assertContains(response, "student")
        self.assertContains(response, "prof")

    def test_roster_link_visible_to_instructor(self):
        """Instructors must see the roster link in the sidebar."""
        self.client.force_login(self.instructor)
        response = self.client.get(reverse("amos:dashboard"))
        self.assertContains(response, reverse("amos:roster"))

    def test_roster_shows_instructor_badge(self):
        """The roster must display an 'Instructor' badge for instructor accounts."""
        self.client.force_login(self.instructor)
        response = self.client.get(reverse("amos:roster"))
        self.assertContains(response, "Instructor")

    def test_promoting_user_grants_roster_access(self):
        """Adding a user to the instructor group must immediately unlock the roster."""
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(reverse("amos:roster")).status_code, 403)
        self.user.groups.add(self.group)
        self.assertEqual(self.client.get(reverse("amos:roster")).status_code, 200)

    def test_demoting_instructor_revokes_roster_access(self):
        """Removing a user from the instructor group must immediately block the roster."""
        self.client.force_login(self.instructor)
        self.assertEqual(self.client.get(reverse("amos:roster")).status_code, 200)
        self.instructor.groups.remove(self.group)
        self.assertEqual(self.client.get(reverse("amos:roster")).status_code, 403)
