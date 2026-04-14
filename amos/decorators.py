"""
amos/decorators.py

View decorators for role-based access control.

These sit one level above authentication — they assume a user is (or should be)
logged in and additionally check group membership before allowing access.

Docs: https://docs.djangoproject.com/en/5.2/topics/auth/default/#limiting-access-to-logged-in-users
Docs: https://docs.djangoproject.com/en/5.2/ref/exceptions/#django.core.exceptions.PermissionDenied
"""

from functools import wraps

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied


def instructor_required(view_func):
    """Allow access only to members of the 'instructor' group.

    Unauthenticated requests are forwarded to the login page (via login_required).
    Authenticated users who are not instructors receive 403 Forbidden so the
    distinction between "not logged in" and "logged in but not permitted" is clear.

    Docs: https://docs.djangoproject.com/en/5.2/topics/auth/default/#groups
    """
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not request.user.groups.filter(name="instructor").exists():
            raise PermissionDenied
        return view_func(request, *args, **kwargs)

    # login_required wraps _wrapped: authentication is checked first, then
    # the group membership check inside _wrapped runs only for logged-in users.
    return login_required(_wrapped)
