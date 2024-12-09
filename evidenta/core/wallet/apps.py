from django.apps import AppConfig


class WalletConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "evidenta.core.wallet"
    label = "user_wallet"
    verbose_name = "User password wallet"
