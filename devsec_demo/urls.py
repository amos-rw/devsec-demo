"""
URL configuration for devsec_demo project.

All amos authentication routes are included under the /amos/ prefix.
Using include() keeps this file clean and lets the amos app manage its
own URL patterns independently.

Docs: https://docs.djangoproject.com/en/5.2/topics/http/urls/#including-other-urlconfs
"""

from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView

urlpatterns = [
    # Redirect the bare root to the login page so visiting / works naturally.
    path('', RedirectView.as_view(pattern_name='amos:login', permanent=False)),

    path('admin/', admin.site.urls),

    # Mount the amos authentication app at /amos/
    path('amos/', include('amos.urls')),
]
