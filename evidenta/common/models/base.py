from typing import Any

from django.core.exceptions import FieldDoesNotExist, ValidationError
from django.db import models
from django.utils import timezone

from evidenta.common.enums import ApiErrorCode
from evidenta.common.validators import BaseDataValidator


class BaseModel(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

    def save(self, *args, **kwargs) -> None:
        self.full_clean()
        super().save(*args, **kwargs)

    def update(self, **data: dict[str, Any]) -> None:
        for field_name, value in data.items():
            try:
                if (field := self._meta.get_field(field_name)).is_relation and not isinstance(field, models.ForeignKey):
                    getattr(self, field_name).set(value)
                else:
                    setattr(self, field_name, value)
            except FieldDoesNotExist as e:
                raise ValidationError(
                    f"Field {field_name} does not exist",
                    params={"field": "field_name", "value": value},
                    code=ApiErrorCode.FIELD_DOES_NOT_EXIST,
                ) from e


class BaseTokenModel(BaseModel):
    user = models.ForeignKey("user.User", on_delete=models.CASCADE)
    expires_at = models.DateTimeField()

    class Meta:
        abstract = True

    def __str__(self) -> str:
        return self.token

    def is_valid(self):
        return timezone.now() < self.expires_at


class BaseModelManagerMixin:
    data_validator = BaseDataValidator

    def clean_and_validate_data(cls, user_data: dict[str, any]) -> None:
        cls.clean_data(user_data)
        cls.data_validator.validate_data(user_data)

    @staticmethod
    def clean_data(user_data: dict[str, any]) -> None:
        pass
