"""
amos/apps.py

AppConfig is Django's way to configure an application and run startup code.
The ready() method is the correct place to connect signals — it fires once
the full app registry is loaded, which avoids import-order problems.

Docs: https://docs.djangoproject.com/en/5.2/ref/applications/#django.apps.AppConfig.ready
Docs: https://docs.djangoproject.com/en/5.2/topics/signals/#connecting-receiver-functions
"""

from django.apps import AppConfig


class AmosConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "amos"

    def ready(self):
        # Importing the signals module here registers the @receiver decorators.
        # The noqa comment suppresses the "imported but unused" linter warning —
        # the import IS the side effect we want.
        import amos.signals  # noqa: F401
