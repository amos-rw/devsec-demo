"""
amos/urls.py

URL patterns for the amos authentication app.

app_name sets the application namespace. This means every reverse lookup
must be prefixed:  reverse('amos:login')  or  {% url 'amos:login' %}.
Namespacing prevents collisions if other apps define views with the same names.

Docs: https://docs.djangoproject.com/en/5.2/topics/http/urls/#url-namespaces
"""

from django.urls import path

from . import views

app_name = "amos"

urlpatterns = [
    # --- Public ---
    path("register/", views.register, name="register"),
    path("login/", views.user_login, name="login"),

    # --- Protected ---
    path("dashboard/", views.dashboard, name="dashboard"),
    path("profile/", views.profile, name="profile"),
    path("password-change/", views.password_change, name="password_change"),
    path("logout/", views.user_logout, name="logout"),
]
