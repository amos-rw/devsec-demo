"""
amos/views.py — authentication lifecycle views.
Docs: https://docs.djangoproject.com/en/5.2/topics/auth/default/
"""

from django.contrib import messages
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect
from django.shortcuts import redirect, render
from django.utils.http import url_has_allowed_host_and_scheme

from .decorators import instructor_required
from .forms import LoginForm, ProfileUpdateForm, RegistrationForm
from .models import Profile


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
    if request.user.is_authenticated:
        return redirect("amos:dashboard")

    if request.method == "POST":
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            messages.success(request, f"Welcome back, {user.username}!")

            # Open-redirect guard: validate ?next= before following it.
            # Without this check an attacker could craft a link that sends
            # the victim to an external site after a successful login.
            # Docs: https://docs.djangoproject.com/en/5.2/ref/utils/#django.utils.http.url_has_allowed_host_and_scheme
            next_url = request.POST.get("next") or request.GET.get("next", "")
            if next_url and url_has_allowed_host_and_scheme(
                url=next_url,
                allowed_hosts={request.get_host()},
                require_https=request.is_secure(),
            ):
                return HttpResponseRedirect(next_url)

            return redirect("amos:dashboard")
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
