from typing import Any

from django.core.exceptions import ObjectDoesNotExist, ValidationError

from graphql.error import GraphQLError, GraphQLFormattedError

from evidenta.common.enums import ApiErrorCode


class InvalidFieldValueException(ValidationError):
    error_code = ApiErrorCode.UNEXPECTED_ERROR

    def __init__(self, message, params: dict[str, any] = None) -> None:
        super().__init__(message=message, params=params)


class InvalidEnumValueException(InvalidFieldValueException):
    pass


class InvalidDateException(InvalidFieldValueException):
    pass


class IntegrityException(InvalidFieldValueException):
    pass


class NonUniqueErrorException(InvalidFieldValueException):
    error_code = ApiErrorCode.UNEXPECTED_ERROR


class RecordDoesNotExist(ObjectDoesNotExist):
    error_code = ApiErrorCode.OBJECT_NOT_FOUND

    def __init__(self, *args, params: dict[str, any] = None, **kwargs):
        self.params = params
        super().__init__(*args, **kwargs)


class GraphqlApiException(GraphQLError):
    def __init__(self, original_error: Exception = None, error_dict: dict[str, any] = None):
        message = (
            getattr(original_error, "message", f"Unexpected error: {str(original_error)}")
            if original_error
            else error_dict.get("message") if error_dict else "Undefined error"
        )
        code = (
            getattr(original_error, "error_code", ApiErrorCode.UNEXPECTED_ERROR).value
            if original_error
            else error_dict.get("error_code").value if error_dict else ApiErrorCode.UNEXPECTED_ERROR.value
        )
        params = (
            getattr(original_error, "params", {})
            if original_error
            else error_dict.get("params", {}) if error_dict else {}
        )
        super().__init__(
            message=message,
            extensions={
                "code": code,
                **params,
            },
        )


class GraphqlApiFormattedError(GraphQLFormattedError):
    error_code: str
    error_data: dict[str, Any]


class BaseApiException(GraphQLError):
    def __init__(
        self,
        message: str,
        error_data: dict[str, Any] | list[dict[str, Any]] = None,
        error_code: ApiErrorCode = ApiErrorCode.UNEXPECTED_ERROR,
    ):
        self.error_data = error_data
        self.error_code = error_code
        super().__init__(message)

    def to_dict(self):
        return {
            "message": self.message,
            "error_data": self.error_data,
            "error_code": self.error_code.value,
        }


class ObjectDoesNotExistApiException(BaseApiException):
    pass


class InvalidDataApiException(BaseApiException):
    pass


class PermissionDeniedApiException(BaseApiException):
    pass


class UnexpectedApiError(BaseApiException):
    pass


class InvalidTokenApiException(BaseApiException):
    pass
