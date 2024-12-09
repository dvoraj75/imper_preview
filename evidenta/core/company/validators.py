from django.core.exceptions import ValidationError

from evidenta.common.validators import BaseDataValidator, BaseValidator


class CompanyIdentificationNumberValidator(BaseValidator):
    def __call__(self, value):
        sum_: int = sum(map(lambda x: x[0] * int(x[1]), enumerate(value[:7][::-1], start=2)))
        mod: int = sum_ % 11
        valid = mod == 0 and int(value[-1]) == 1 or mod == 1 and int(value[-1]) == 0 or int(value[-1]) == 11 - mod
        if not valid:
            raise ValidationError(f"Validation error: invalid company identification number: {value}")


class CompanyDataValidator(BaseDataValidator):
    validators = {}
