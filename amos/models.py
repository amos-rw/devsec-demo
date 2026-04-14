"""
amos/models.py

We extend Django's built-in User with a Profile using a OneToOneField.
This is the recommended approach when you need extra user data but do not
need to change how authentication itself works.

Docs: https://docs.djangoproject.com/en/5.2/topics/auth/customizing/#extending-the-existing-user-model
"""

from django.contrib.auth.models import User
from django.db import models


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
