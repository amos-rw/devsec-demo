"""
amos/signals.py

Django signals let us hook into model lifecycle events without modifying
the model itself. Here we listen for the post_save signal on User so that
a Profile is automatically created whenever a new User is saved.

This guarantees every user has a profile regardless of how the user was
created — registration form, Django admin, management command, etc.

Docs: https://docs.djangoproject.com/en/5.2/topics/signals/
Docs: https://docs.djangoproject.com/en/5.2/ref/signals/#post-save
"""

from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import Profile


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    Fires after a User is saved. When created=True it is a brand-new user,
    so we create the accompanying Profile. get_or_create is used as a
    defensive guard against duplicate-signal edge cases.
    """
    if created:
        Profile.objects.get_or_create(user=instance)
