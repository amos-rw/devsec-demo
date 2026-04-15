"""
amos/models.py

We extend Django's built-in User with a Profile using a OneToOneField.
This is the recommended approach when you need extra user data but do not
need to change how authentication itself works.

Docs: https://docs.djangoproject.com/en/5.2/topics/auth/customizing/#extending-the-existing-user-model
"""

from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone


class Profile(models.Model):
    """
    Stores extra information tied to a registered user.

    OneToOneField enforces a strict 1-to-1 relationship:
      - Each User has exactly one Profile.
      - Deleting a User automatically deletes its Profile (CASCADE).
      - related_name='profile' lets us write request.user.profile cleanly.

    Docs: https://docs.djangoproject.com/en/5.2/ref/models/fields/#onetoonefield
    """

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="profile",
    )
    bio = models.TextField(
        max_length=500,
        blank=True,
        help_text="A short bio shown on your profile page (500 characters max).",
    )

    class Meta:
        verbose_name = "Profile"
        verbose_name_plural = "Profiles"

    def __str__(self):
        return f"{self.user.username}'s profile"


class LoginAttempt(models.Model):
    """
    Tracks consecutive failed login attempts per username for brute-force
    protection.

    Design: account-based (keyed on normalised username, not IP address).
    - Pros: works behind load balancers and NAT; directly protects accounts.
    - Cons: a determined attacker knowing a username could trigger a lockout
      to deny service.  That tradeoff is documented in the assignment PR.

    The view resets this record on successful login and also resets the
    counter once a lockout period has fully expired.

    Docs: https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks
    """

    # Normalised (lowercased) username — not a FK because we want to track
    # attempts for usernames that may not even exist in the database.
    username = models.CharField(max_length=150, unique=True, db_index=True)
    failed_count = models.PositiveIntegerField(default=0)
    last_failed_at = models.DateTimeField(null=True, blank=True)
    # NULL means not currently locked.
    locked_until = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Login Attempt"
        verbose_name_plural = "Login Attempts"

    def __str__(self):
        return f"{self.username} — {self.failed_count} failed attempt(s)"

    @property
    def is_locked(self) -> bool:
        """True if the lockout window is still active."""
        return self.locked_until is not None and self.locked_until > timezone.now()
