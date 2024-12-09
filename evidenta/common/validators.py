import enum

from django.utils.deconstruct import deconstructible

from evidenta.common.exceptions import InvalidFieldValueException


@deconstructible
class BaseValidator:
    def __init__(
        self,
        required: bool = False,
        exception_cls: type[Exception] = InvalidFieldValueException,
    ):
        self.required = required
        self.exception_cls = exception_cls


class EnumValidator(BaseValidator):
    def __init__(self, enum_: type[enum.Enum], **kwargs):
        self.enum_ = enum_
        super().__init__(**kwargs)

    def __call__(self, value):
        if (value is not None and value not in self.enum_) or (self.required and not value):
            raise self.exception_cls(f"Invalid value for {self.enum_.__name__}", params={"field": value})


class BaseDataValidator:
    validators = {}

    @classmethod
    def validate_data(cls, user_data: dict[str, any]) -> None:
        for field, value in user_data.items():
            if validator := cls.validators.get(field):
                validator(value)
