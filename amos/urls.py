"""
amos/urls.py

URL patterns for the amos authentication app.

app_name sets the application namespace. This means every reverse lookup
must be prefixed:  reverse('amos:login')  or  {% url 'amos:login' %}.
Namespacing prevents collisions if other apps define views with the same names.

Docs: https://docs.djangoproject.com/en/5.2/topics/http/urls/#url-namespaces
"""

from django.contrib.auth import views as auth_views
from django.urls import path, reverse_lazy

from . import views

app_name = "amos"

urlpatterns = [
    # --- Public ---
    path("register/", views.register, name="register"),
    path("login/", views.user_login, name="login"),

    # --- Password reset (public — user is locked out and cannot authenticate) ---
    # Django's built-in views handle token generation, validation, and expiry.
    # We only supply templates and the success redirect URLs.
    # Docs: https://docs.djangoproject.com/en/5.2/topics/auth/default/#django.contrib.auth.views.PasswordResetView
    path(
        "password-reset/",
        views.AuditedPasswordResetView.as_view(
            template_name="amos/password_reset_request.html",
            email_template_name="amos/email/password_reset_email.txt",
            subject_template_name="amos/email/password_reset_subject.txt",
            success_url=reverse_lazy("amos:password_reset_done"),
        ),
        name="password_reset",
    ),
    path(
        "password-reset/done/",
        auth_views.PasswordResetDoneView.as_view(
            template_name="amos/password_reset_done.html",
        ),
        name="password_reset_done",
    ),
    # <uidb64>/<token>/ — Django validates the token here; a valid token is
    # stored in the session and the URL is rewritten to .../set-password/ to
    # prevent the token from appearing in the Referer header on the next page.
    path(
        "password-reset/<uidb64>/<token>/",
        views.AuditedPasswordResetConfirmView.as_view(
            template_name="amos/password_reset_confirm.html",
            success_url=reverse_lazy("amos:password_reset_complete"),
        ),
        name="password_reset_confirm",
    ),
    path(
        "password-reset/complete/",
        auth_views.PasswordResetCompleteView.as_view(
            template_name="amos/password_reset_complete.html",
        ),
        name="password_reset_complete",
    ),

    # --- Authenticated users ---
    path("dashboard/", views.dashboard, name="dashboard"),
    path("profile/", views.profile, name="profile"),
    path("password-change/", views.password_change, name="password_change"),
    path("logout/", views.user_logout, name="logout"),

    # --- Profile detail (object-level access control enforced in the view) ---
    path("profile/<int:pk>/", views.view_profile, name="view_profile"),

    # --- AJAX bio update (CSRF enforced — no @csrf_exempt) ---
    # JavaScript callers must include the csrftoken cookie value in the
    # X-CSRFToken request header.  See update_bio docstring and profile.html.
    path("profile/bio/", views.update_bio, name="update_bio"),

    # --- Instructor only ---
    path("roster/", views.roster, name="roster"),
]
