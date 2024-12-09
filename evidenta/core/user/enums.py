from enum import Enum, auto

from django.db.models import IntegerChoices
from django.utils.translation import gettext_lazy as _


class UserRole(IntegerChoices):
    GUEST = auto(), _("Guest")
    CLIENT = auto(), _("Client")
    ACCOUNTANT = auto(), _("Accountant")
    SUPERVISOR = auto(), _("Supervisor")
    ADMIN = auto(), _("Admin")


class UserGender(IntegerChoices):
    MALE = auto(), _("Male")
    FEMALE = auto(), _("Female")


class ResourcePath(Enum):
    SETUP_PASSWORD = "/setup-password/{token}"  # noqa: S105
    RESET_PASSWORD = "/reset-password/{token}"  # noqa: S105

    def format(self, **kwargs) -> str:
        return self.value.format(**kwargs)
