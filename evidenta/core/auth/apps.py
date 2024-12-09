from django.apps import AppConfig


class UserConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "evidenta.core.auth"
    label = "custom_auth"
    verbose_name = "Custom auth app"
