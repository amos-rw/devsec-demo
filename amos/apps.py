"""
amos/apps.py

AppConfig is Django's way to configure an application and run startup code.
The ready() method is the correct place to connect signals — it fires once
the full app registry is loaded, which avoids import-order problems.

Docs: https://docs.djangoproject.com/en/5.2/ref/applications/#django.apps.AppConfig.ready
Docs: https://docs.djangoproject.com/en/5.2/topics/signals/#connecting-receiver-functions
"""

from django.apps import AppConfig
from django.db.models.signals import post_migrate


class AmosConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "amos"

    def ready(self):
        import amos.signals  # noqa: F401
        # Ensure role groups exist after every migration run (idempotent).
        # post_migrate fires after `migrate` and after the test-runner sets up
        # the test database, so groups are always present without manual steps.
        # Docs: https://docs.djangoproject.com/en/5.2/ref/signals/#post-migrate
        post_migrate.connect(_ensure_roles, sender=self)


def _ensure_roles(sender, **kwargs):
    """Create the role groups that drive authorization decisions.

    Using get_or_create means this is safe to run repeatedly — no duplicates.
    New roles can be added to the tuple as the project grows.
    """
    from django.contrib.auth.models import Group

    for name in ("instructor",):
        Group.objects.get_or_create(name=name)
