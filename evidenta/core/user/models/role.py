from django.contrib.auth.models import Permission
from django.db import models

from evidenta.common.models.base import BaseModel
from evidenta.core.user.enums import UserRole


class Role(BaseModel):
    role = models.PositiveSmallIntegerField(choices=UserRole.choices, unique=True, null=True)
    permissions = models.ManyToManyField(Permission, blank=True)

    def __str__(self) -> str:
        return str(UserRole(self.role).label)

    def __eq__(self, other):
        return self.role == other

    def __hash__(self):
        return super().__hash__()
