from django.apps import AppConfig


class CompanyConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "evidenta.core.company"
    label = "company"
    verbose_name = "Company"
