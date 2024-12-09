from django.core.exceptions import ValidationError


class InvalidTokenError(ValidationError):
    pass
