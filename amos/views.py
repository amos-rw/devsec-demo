"""
amos/views.py — authentication lifecycle views.
Docs: https://docs.djangoproject.com/en/5.2/topics/auth/default/
"""

import json
from datetime import timedelta

from django.contrib import messages
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from .decorators import instructor_required
from .forms import LoginForm, ProfileUpdateForm, RegistrationForm
from .models import LoginAttempt, Profile

# ---------------------------------------------------------------------------
# Brute-force protection settings
# After MAX_ATTEMPTS consecutive failures the account is locked for
# LOCKOUT_DURATION.  The counter resets on a successful login or once the
# lockout window has fully expired.
# ---------------------------------------------------------------------------
_MAX_ATTEMPTS = 5
_LOCKOUT_DURATION = timedelta(minutes=15)


def register(request):
    if request.user.is_authenticated:
        return redirect("amos:dashboard")

    if request.method == "POST":
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, f"Welcome, {user.username}! Your account is ready.")
            return redirect("amos:dashboard")
    else:
        form = RegistrationForm()

    return render(request, "amos/register.html", {"form": form})


def user_login(request):
    """Authenticate a user and redirect them to their intended destination.

    Open-redirect risk
    ------------------
    The login page accepts a ``?next=`` query-string parameter so the user
    lands on the page they originally requested after authenticating.  Without
    validation, an attacker can craft a link like::

        /amos/login/?next=http://evil.com/phish

    The user authenticates on the real site, sees the familiar domain in the
    address bar, and is then silently forwarded to the attacker's page.  Because
    they just "logged in" they trust the destination.

    Fix applied here
    ----------------
    Every ``next=`` value is passed through Django's
    ``url_has_allowed_host_and_scheme()`` utility before use.  That helper
    rejects:

    * absolute URLs pointing to foreign hosts  (``http://evil.com/…``)
    * protocol-relative URLs                   (``//evil.com/…``)
    * ``javascript:`` and ``data:`` URI schemes
    * any URL whose netloc does not match ``request.get_host()``

    Safe same-origin paths (e.g. ``/amos/profile/``) are followed unchanged.
    When the value is absent or rejected the user lands on the dashboard.

    Docs: https://docs.djangoproject.com/en/5.2/ref/utils/#django.utils.http.url_has_allowed_host_and_scheme
    """
    if request.user.is_authenticated:
        return redirect("amos:dashboard")

    if request.method == "POST":
        # Normalise username for consistent tracking regardless of case.
        raw_username = request.POST.get("username", "").strip()
        attempt_key  = raw_username.lower()

        attempt, _ = LoginAttempt.objects.get_or_create(username=attempt_key)
        now = timezone.now()

        # ── Guard: reject immediately if still within lockout window ──────
        # We check this BEFORE running the (expensive) credential check so a
        # locked account cannot be used to probe passwords at all.
        if attempt.locked_until and attempt.locked_until > now:
            remaining = max(1, round((attempt.locked_until - now).total_seconds() / 60))
            messages.error(
                request,
                f"Too many failed attempts. Please wait {remaining} minute(s) before trying again.",
            )
            return render(request, "amos/login.html", {
                # Return a blank form — no point showing credential errors
                # when the account is locked regardless.
                "form": LoginForm(),
                "next": request.POST.get("next", ""),
            })

        # ── Reset counter once lockout window has fully elapsed ───────────
        # This gives the user a clean slate for the next window rather than
        # requiring admin intervention to unlock.
        if attempt.locked_until and attempt.locked_until <= now:
            attempt.failed_count = 0
            attempt.locked_until = None
            attempt.save()

        # ── Normal authentication ─────────────────────────────────────────
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)

            # Clear the attempt record — clean slate for next session.
            attempt.delete()

            messages.success(request, f"Welcome back, {user.username}!")

            # Open-redirect guard: validate ?next= before following it.
            # Docs: https://docs.djangoproject.com/en/5.2/ref/utils/#django.utils.http.url_has_allowed_host_and_scheme
            next_url = request.POST.get("next") or request.GET.get("next", "")
            if next_url and url_has_allowed_host_and_scheme(
                url=next_url,
                allowed_hosts={request.get_host()},
                require_https=request.is_secure(),
            ):
                return HttpResponseRedirect(next_url)

            return redirect("amos:dashboard")

        # ── Record failure ────────────────────────────────────────────────
        attempt.failed_count += 1
        attempt.last_failed_at = now
        if attempt.failed_count >= _MAX_ATTEMPTS:
            attempt.locked_until = now + _LOCKOUT_DURATION
        attempt.save()

    else:
        form = LoginForm()

    return render(request, "amos/login.html", {
        "form": form,
        "next": request.GET.get("next", ""),
    })


@login_required
def dashboard(request):
    return render(request, "amos/dashboard.html")


@login_required
def profile(request):
    # get_or_create is a safety net for users created outside the registration
    # form (e.g. via django admin or fixtures) who may not have a Profile yet.
    profile_obj, _ = Profile.objects.get_or_create(user=request.user)

    if request.method == "POST":
        form = ProfileUpdateForm(request.POST, instance=profile_obj)
        if form.is_valid():
            form.save()
            messages.success(request, "Your profile has been updated.")
            return redirect("amos:profile")
    else:
        form = ProfileUpdateForm(instance=profile_obj)

    return render(request, "amos/profile.html", {"form": form})


@login_required
def password_change(request):
    if request.method == "POST":
        form = PasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            user = form.save()
            # update_session_auth_hash keeps the current session alive after
            # the password hash rotates, so the user is not signed out here.
            # Docs: https://docs.djangoproject.com/en/5.2/topics/auth/default/#django.contrib.auth.update_session_auth_hash
            update_session_auth_hash(request, user)
            messages.success(request, "Your password has been changed successfully.")
            return redirect("amos:dashboard")
    else:
        form = PasswordChangeForm(user=request.user)

    return render(request, "amos/password_change.html", {"form": form})


@instructor_required
def roster(request):
    # select_related prefetches the profile in the same query to avoid N+1 hits.
    # Docs: https://docs.djangoproject.com/en/5.2/ref/models/querysets/#select-related
    users = User.objects.select_related("profile").order_by("date_joined")
    return render(request, "amos/roster.html", {"users": users})


@login_required
def user_logout(request):
    # POST-only logout prevents a CSRF-style attack where an attacker embeds
    # the logout URL in an <img> tag and silently signs the victim out.
    if request.method == "POST":
        logout(request)
        messages.info(request, "You have been signed out. See you next time!")
        return redirect("amos:login")

    return render(request, "amos/logout_confirm.html")


@login_required
def view_profile(request, pk):
    """Read-only view of a single user's profile, looked up by primary key.

    IDOR risk: this endpoint accepts a predictable integer (the user's pk) in
    the URL.  Without an explicit ownership check, any authenticated user could
    read any other user's profile simply by changing that number — a classic
    Insecure Direct Object Reference (IDOR) attack.

    Fix applied here: before touching the database we verify that the requesting
    user either *owns* the profile (request.user.pk == pk) or holds the
    'instructor' role.  Everyone else receives 403 Forbidden.  We raise the
    error before calling get_object_or_404 so we do not accidentally leak the
    existence of accounts to unauthorised callers.

    Docs: https://docs.djangoproject.com/en/5.2/topics/auth/default/#limiting-access-to-logged-in-users
    Docs: https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control
    """
    is_instructor = request.user.groups.filter(name="instructor").exists()

    # Object-level access check — explicit, not implicit.
    # Checking login state alone is not enough; we must also verify ownership.
    if request.user.pk != pk and not is_instructor:
        raise PermissionDenied

    target_user = get_object_or_404(User, pk=pk)
    # get_or_create is a safety net for users who may not have a Profile yet
    # (e.g. created via management commands or fixtures).
    profile_obj, _ = Profile.objects.get_or_create(user=target_user)

    return render(request, "amos/view_profile.html", {
        "profile_user": target_user,
        "profile_obj": profile_obj,
    })


@login_required
@require_POST
def update_bio(request):
    """AJAX endpoint: update the current user's bio and return JSON.

    CSRF concern
    ------------
    This is a state-changing POST that is called over JavaScript fetch().
    The tempting shortcut — adding ``@csrf_exempt`` to 'make it work' — removes
    ALL forgery protection.  Any page on any origin could then silently update
    the bio of any logged-in user (a classic CSRF attack).

    Fix applied here
    ----------------
    No exemption is added.  Django's CsrfViewMiddleware stays fully active.
    The JavaScript caller is responsible for reading the ``csrftoken`` cookie
    (which is intentionally NOT HttpOnly so JS can access it) and sending the
    value in the ``X-CSRFToken`` request header.  The middleware validates the
    header against the cookie on every POST.

    Docs: https://docs.djangoproject.com/en/5.2/howto/csrf/#ajax
    """
    try:
        payload = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON."}, status=400)

    bio = payload.get("bio", "").strip()

    if len(bio) > 500:
        return JsonResponse(
            {"error": "Bio must be 500 characters or fewer."},
            status=400,
        )

    profile, _ = Profile.objects.get_or_create(user=request.user)
    profile.bio = bio
    profile.save()

    return JsonResponse({"status": "ok"})
