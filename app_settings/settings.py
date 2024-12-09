import os
from pathlib import Path

from django.utils.translation import gettext_lazy as _

import environ


env = environ.Env()
# Build paths inside the project like this: BASE_DIR / 'subdir'.

BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env("SECRET_KEY")  # noqa:S105
# SECURITY WARNING: keep the secret key used in production secret!
WALLET_SECRET_KEY = env("WALLET_SECRET_KEY")  # noqa:S105

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = env.bool("DEBUG", default=False)
PRODUCTION = env.bool("PRODUCTION", default=True)
FRONTEND_URL = env("FRONTEND_URL")

WALLET_KEY_LEN = env.int("WALLET_KEY_LEN", default=16)

ALLOWED_HOSTS = ["*"]

CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "https://localhost:5173",
    "http://127.0.0.1:5173",
    "https://127.0.0.1:5173",
]
CORS_ALLOW_METHODS = [
    "POST",
]

CORS_ALLOW_HEADERS = [
    "content-type",
    "x-csrftoken",
]

CORS_ALLOW_CREDENTIALS = True

INSTALLED_APPS = [
    "evidenta.common",
    "evidenta.core.company",
    "evidenta.core.user",
    "evidenta.core.auth",
    "evidenta.core.wallet",
    "corsheaders",
    "graphene_django",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "graphql_jwt.refresh_token.apps.RefreshTokenConfig",
    "django_filters",
]

GRAPHENE = {
    "SCHEMA": "evidenta.schema.schema",
    "MIDDLEWARE": [
        "graphql_jwt.middleware.JSONWebTokenMiddleware",
        "evidenta.middleware.refresh_token.RefreshTokenMiddleware",
    ],
}

GRAPHQL_JWT = {
    "JWT_VERIFY_EXPIRATION": True,
    "JWT_LONG_RUNNING_REFRESH_TOKEN": True,
    "JWT_ALLOW_ANY_CLASSES": [
        "graphql_jwt.relay.ObtainJSONWebToken",
        "graphql_jwt.relay.Revoke",
        "graphql_jwt.relay.Verify",
        "graphql_jwt.relay.Refresh",
    ],
    "JWT_COOKIE_SECURE": PRODUCTION,
    "JWT_HIDE_TOKEN_FIELDS": True,
    "JWT_COOKIE_SAMESITE": "strict",
    "JWT_REUSE_REFRESH_TOKENS": True,
}

AUTH_USER_MODEL = "user.User"

AUTHENTICATION_BACKENDS = [
    "graphql_jwt.backends.JSONWebTokenBackend",
    "django.contrib.auth.backends.ModelBackend",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "app_settings.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "app_settings.wsgi.application"


# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases
if not os.environ.get("GITHUB_WORKFLOW"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": env("DB_NAME"),
            "USER": env("DB_USER"),
            "PASSWORD": env("DB_PASSWORD"),
            "HOST": env("DB_HOSTNAME"),
            "PORT": env("DB_PORT"),
        }
    }

# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/

LANGUAGE_CODE = "en-us"
LANGUAGES = [
    ("cs", _("Czech")),
    ("en", _("English")),
]
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
LOCALE_PATHS = [os.path.join(BASE_DIR, "locale")]

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/

STATIC_URL = "static/"

# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# Default folder for saving data
MEDIA_ROOT = os.path.join(BASE_DIR, "media/")

DATE_FORMAT = "%Y-%m-%d"
TIME_FORMAT = "%H:%M:%S"
DATE_TIME_FORMAT = f"{DATE_FORMAT} {TIME_FORMAT}"

DEFAULT_TOKEN_LENGTH = env.int("AUTH_DEFAULT_TOKEN_LENGTH", default=64)
DEFAULT_OTP_TOKEN_LENGTH = env.int("AUTH_DEFAULT_OTP_TOKEN_LENGTH", default=6)
INVITATION_LINK_TOKEN_EXPIRATION_MINS = env.int("AUTH_INVITATION_LINK_TOKEN_EXPIRATION_MINS", default=1 * 24 * 60)
RESET_PASSWORD_LINK_TOKEN_EXPIRATION_MINS = env.int("AUTH_RESET_PASSWORD_LINK_TOKEN_EXPIRATION_MINS", default=120)
CHANGE_PASSWORD_OTP_TOKEN_EXPIRATION_MINS = env.int("AUTH_CHANGE_PASSWORD_OTP_TOKEN_EXPIRATION_MINS", default=15)
WALLET_UNLOCK_EXPIRATION_TIME_MINS = env.int("WALLET_UNLOCK_EXPIRATION_TIME", default=15)
