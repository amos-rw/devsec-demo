"""
Django settings for devsec_demo project.

Environment variables (set in .env for development, in the host for production)
--------------------------------------------------------------------------------
  DJANGO_SECRET_KEY     Required in production.  A dev placeholder is used when
                        DEBUG=True and this is not set, with a loud warning.
  DJANGO_DEBUG          '1'/'true'/'yes' → True.  Anything else → False.
                        Defaults to False (safe default).
  DJANGO_ALLOWED_HOSTS  Comma-separated list of allowed hostnames.
                        Required when DEBUG=False.
  DJANGO_HTTPS          '1'/'true'/'yes' → enables HTTPS-specific controls
                        (SSL redirect, HSTS, Secure cookies).  Default: False.

Deployment checklist:
  https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/
"""

import os
import warnings
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Environment-variable helpers
# ---------------------------------------------------------------------------

def _env(key, default=None):
    """Return the value of environment variable *key*, or *default*."""
    return os.environ.get(key, default)


def _env_bool(key, default=False):
    """
    Parse a boolean from an environment variable.

    Why not just os.environ.get()?
    --------------------------------
    os.environ.get('KEY') returns a STRING, not a boolean.  In Python, every
    non-empty string is truthy, so DEBUG = os.environ.get('DJANGO_DEBUG') gives
    DEBUG = 'False' which evaluates to True in an if-statement — a silent bug
    that leaves DEBUG on even when the operator intended to turn it off.

    This helper converts '1', 'true', or 'yes' (case-insensitive) to True and
    anything else to False, making the conversion explicit and correct.
    """
    val = os.environ.get(key)
    if val is None:
        return default
    return val.strip().lower() in ('1', 'true', 'yes')


# ---------------------------------------------------------------------------
# Core security — DEBUG, SECRET_KEY, ALLOWED_HOSTS
# ---------------------------------------------------------------------------

# Parse DEBUG as a real boolean (not a string).  Default False = secure default.
DEBUG = _env_bool('DJANGO_DEBUG', default=False)

# SECRET_KEY must be a strong, secret random string.
# Never fall back to a hardcoded value in production — if it leaks, an attacker
# can forge signed cookies and session tokens.
_secret = _env('DJANGO_SECRET_KEY')
if not _secret:
    if DEBUG:
        _secret = 'dev-only-insecure-placeholder-must-not-be-used-in-production'
        warnings.warn(
            "DJANGO_SECRET_KEY is not set.  A weak placeholder is in use. "
            "Generate a strong key and set it before deploying to production.",
            stacklevel=2,
        )
    else:
        raise ImproperlyConfigured(
            "DJANGO_SECRET_KEY environment variable must be set when DEBUG is False. "
            "Generate one with: python -c \"from django.core.management.utils import "
            "get_random_secret_key; print(get_random_secret_key())\""
        )
SECRET_KEY = _secret

# ALLOWED_HOSTS rejects requests whose Host header is not in this list.
# Django skips the check when DEBUG=True, but the list must be explicit in
# production — an empty list with DEBUG=False causes HTTP 400 for every request.
_raw_hosts = _env('DJANGO_ALLOWED_HOSTS', '')
ALLOWED_HOSTS = [h.strip() for h in _raw_hosts.split(',') if h.strip()]
if not ALLOWED_HOSTS:
    if DEBUG:
        # Safe development defaults.  'testserver' is the hostname Django's
        # test client uses so tests pass without separate configuration.
        ALLOWED_HOSTS = ['localhost', '127.0.0.1', '[::1]', 'testserver']
    else:
        raise ImproperlyConfigured(
            "DJANGO_ALLOWED_HOSTS environment variable must be set when DEBUG is False. "
            "Example: DJANGO_ALLOWED_HOSTS=example.com,www.example.com"
        )


# ---------------------------------------------------------------------------
# Application definition
# ---------------------------------------------------------------------------

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # --- Project apps ---
    'amos',  # User Authentication Service — Amos
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'devsec_demo.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'devsec_demo.wsgi.application'


# ---------------------------------------------------------------------------
# Database
# Docs: https://docs.djangoproject.com/en/5.2/ref/settings/#databases
# ---------------------------------------------------------------------------

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# ---------------------------------------------------------------------------
# Password validation
# Docs: https://docs.djangoproject.com/en/5.2/ref/settings/#auth-password-validators
# ---------------------------------------------------------------------------

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# ---------------------------------------------------------------------------
# Internationalisation
# Docs: https://docs.djangoproject.com/en/5.2/topics/i18n/
# ---------------------------------------------------------------------------

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# ---------------------------------------------------------------------------
# Static files
# Docs: https://docs.djangoproject.com/en/5.2/howto/static-files/
# ---------------------------------------------------------------------------

STATIC_URL = 'static/'


# ---------------------------------------------------------------------------
# User-uploaded media files
# Docs: https://docs.djangoproject.com/en/5.2/topics/files/
# ---------------------------------------------------------------------------
# MEDIA_ROOT must NOT be inside STATIC_ROOT (those files are served without
# access control).  All access to uploaded files goes through the
# amos:serve_file view, which enforces login and ownership checks before
# streaming content.  MEDIA_URL is therefore intentionally NOT wired into
# urls.py.

MEDIA_ROOT = BASE_DIR / 'media'
MEDIA_URL = '/media/'  # used only for internal storage path construction


# ---------------------------------------------------------------------------
# HTTPS / transport security
# Docs: https://docs.djangoproject.com/en/5.2/topics/security/#ssl-https
# ---------------------------------------------------------------------------
# These controls are only meaningful when the application is running behind
# a real HTTPS terminator.  Enable them by setting DJANGO_HTTPS=true in the
# production environment.  Do NOT tie them to DEBUG=False alone — a staging
# server may run on HTTP, and enabling HSTS prematurely can lock users out.

_https = _env_bool('DJANGO_HTTPS', default=False)

# Redirect every plain-HTTP request to HTTPS.
SECURE_SSL_REDIRECT = _https

# HTTP Strict Transport Security: tells browsers to use HTTPS for the next
# year.  Enable only after HTTPS is confirmed working — a premature HSTS
# header is very hard to reverse because browsers cache it locally.
SECURE_HSTS_SECONDS = 31_536_000 if _https else 0   # 1 year once HTTPS is live
SECURE_HSTS_INCLUDE_SUBDOMAINS = _https
SECURE_HSTS_PRELOAD = _https


# ---------------------------------------------------------------------------
# Browser security headers
# Docs: https://docs.djangoproject.com/en/5.2/ref/middleware/#module-django.middleware.security
# ---------------------------------------------------------------------------

# Prevent browsers from MIME-sniffing a response away from the declared
# Content-Type (e.g. treating a text file as executable HTML).
# Django's default is already True; made explicit here for auditability.
SECURE_CONTENT_TYPE_NOSNIFF = True

# Referrer-Policy: send the full URL only for same-origin requests; send
# just the origin for cross-origin HTTPS; send nothing over plain HTTP.
# Prevents leaking internal paths or query strings to third-party servers.
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# Prevent this application from being embedded in an <iframe> on any origin.
# A login service has no legitimate use as a frame target; denying framing
# blocks clickjacking attacks completely.
# Django's XFrameOptionsMiddleware defaults to SAMEORIGIN — DENY is stricter.
X_FRAME_OPTIONS = 'DENY'


# ---------------------------------------------------------------------------
# Cookie security
# Docs: https://docs.djangoproject.com/en/5.2/topics/http/sessions/#session-security
# Docs: https://docs.djangoproject.com/en/5.2/ref/settings/#csrf-cookie-secure
# ---------------------------------------------------------------------------

# Prevent JavaScript from reading the session cookie (mitigates XSS theft).
# Already Django's default; made explicit for clarity.
SESSION_COOKIE_HTTPONLY = True

# Mark session and CSRF cookies as Secure (transmitted over HTTPS only).
# Must be False in development where HTTPS is not available.
SESSION_COOKIE_SECURE = _https
CSRF_COOKIE_SECURE = _https

# SameSite=Lax: the browser omits the cookie in cross-site POST requests
# (a CSRF mitigation layer on top of Django's token check) while still
# sending it for top-level GET navigations (e.g. following a link).
SESSION_COOKIE_SAMESITE = 'Lax'

# CSRF_COOKIE_HTTPONLY is intentionally left False (Django's default).
# The profile page reads the csrftoken cookie value from JavaScript to set
# the X-CSRFToken header on AJAX requests.  Setting HttpOnly here would
# break that pattern.  The CSRF token is not a secret bearer credential —
# its value is already embedded in every HTML form as a hidden field.

# Sessions expire after 1 hour of inactivity (3 600 seconds).
# Django's default is 2 weeks — far too long for an auth service.
SESSION_COOKIE_AGE = 3600


# ---------------------------------------------------------------------------
# Authentication routing
# Docs: https://docs.djangoproject.com/en/5.2/ref/settings/#login-url
# ---------------------------------------------------------------------------

LOGIN_URL = '/amos/login/'
LOGIN_REDIRECT_URL = '/amos/dashboard/'
LOGOUT_REDIRECT_URL = '/amos/login/'


# ---------------------------------------------------------------------------
# Default primary key type
# ---------------------------------------------------------------------------

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# ---------------------------------------------------------------------------
# Email
# Docs: https://docs.djangoproject.com/en/5.2/topics/email/
# ---------------------------------------------------------------------------

# In development the console backend prints outgoing emails to stdout so the
# reset link is visible without needing an SMTP server.
# Swap for an SMTP or third-party backend in production.
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

DEFAULT_FROM_EMAIL = 'UAS <noreply@uas.local>'


# ---------------------------------------------------------------------------
# Password reset token lifetime
# Docs: https://docs.djangoproject.com/en/5.2/ref/settings/#password-reset-timeout
# ---------------------------------------------------------------------------

# Reset links expire after 1 hour (3 600 s).
# Django's default is 3 days — far too long for a short-lived recovery link.
PASSWORD_RESET_TIMEOUT = 3600


# ---------------------------------------------------------------------------
# Audit logging
# Docs: https://docs.djangoproject.com/en/5.2/topics/logging/
# ---------------------------------------------------------------------------
# The "amos.audit" logger captures security-relevant auth events (login,
# logout, registration, password changes).  In production swap the console
# handler for a file handler or ship to a centralised logging service.

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "audit": {
            "format": "%(asctime)s %(levelname)-8s %(name)s %(message)s",
            "datefmt": "%Y-%m-%dT%H:%M:%SZ",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "audit",
        },
    },
    "loggers": {
        "amos.audit": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
