"""
amos/admin.py

We extend Django's built-in UserAdmin with a Profile inline so that the
admin can view and edit a user's bio on the same page as the user account —
no need to navigate to a separate Profile admin page.

We unregister the default User registration first, then re-register it with
our extended admin class. This is the standard Django pattern for modifying
an existing model's admin without changing the model itself.

Docs: https://docs.djangoproject.com/en/5.2/ref/contrib/admin/#inlinemodeladmin-objects
Docs: https://docs.djangoproject.com/en/5.2/topics/auth/customizing/#extending-the-existing-user-model
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User

from .models import LoginAttempt, Profile


class ProfileInline(admin.StackedInline):
    """
    Renders the Profile form inline under the User change page.
    StackedInline shows each field on its own line (as opposed to
    TabularInline which uses a compact table layout).

    can_delete=False prevents accidentally removing the Profile from here,
    since the Profile should live and die with the User via CASCADE.
    """

    model = Profile
    can_delete = False
    verbose_name_plural = "Profile"
    fk_name = "user"


class ExtendedUserAdmin(UserAdmin):
    """
    Adds the ProfileInline to Django's standard UserAdmin.
    All existing UserAdmin behaviour (password change, permissions, etc.)
    is preserved because we only extend it rather than replace it.
    """

    inlines = (ProfileInline,)


# Replace the default User admin with our extended version.
admin.site.unregister(User)
admin.site.register(User, ExtendedUserAdmin)

# Also register Profile on its own so it is searchable/filterable directly.
admin.site.register(Profile)


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    """
    Admin view for brute-force attempt records.
    Allows administrators to inspect and manually clear lockouts.
    """
    list_display  = ("username", "failed_count", "last_failed_at", "locked_until", "is_locked")
    list_filter   = ("locked_until",)
    search_fields = ("username",)
    readonly_fields = ("username", "failed_count", "last_failed_at", "locked_until")

    @admin.display(boolean=True, description="Currently locked?")
    def is_locked(self, obj):
        return obj.is_locked
