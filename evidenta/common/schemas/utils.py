from functools import wraps
from typing import Any, Callable

from django.core.exceptions import ValidationError

from evidenta.common.enums import ERROR_MESSAGES, ApiErrorCode
from evidenta.common.exceptions import (
    InvalidDataApiException,
    InvalidTokenApiException,
    ObjectDoesNotExistApiException,
    PermissionDeniedApiException,
    UnexpectedApiError,
)
from evidenta.core.user.enums import UserRole
from evidenta.core.user.models import User


def login_required(fnc: Callable) -> Callable:
    @wraps(fnc)
    def wrapper(cls, arg, info, *args, **kwargs):
        if info.context.user.is_anonymous:
            raise PermissionDeniedApiException(message="User is not logged in.", error_code=ApiErrorCode.LOGIN_REQUIRED)
        return fnc(cls, arg, info, *args, **kwargs)

    return wrapper


def permissions_required(permissions: list[str]) -> Callable:
    def decorator(fnc: Callable) -> Callable:
        @wraps(fnc)
        def wrapper(cls, arg, info, *args, **kwargs):
            if not info.context.user.has_perms(permissions):
                raise PermissionDeniedApiException(
                    message=f"User '{info.context.user.username}' does not have required permissions.",
                    error_code=ApiErrorCode.PERMISSION_REQUIRED,
                )
            return fnc(cls, arg, info, *args, **kwargs)

        return wrapper

    return decorator


def check_if_user_can_assign_companies(user: User) -> None:
    if not user.has_perm("user.assign_company_user"):
        raise PermissionDeniedApiException(
            message=f"User '{user.username}' does not have permission to assign companies.'",
            error_code=ApiErrorCode.PERMISSION_REQUIRED,
        )


def check_if_user_can_assign_role(user: User, role: UserRole) -> None:
    # todo: trosku ucesat hlasky
    if not user.has_perm("user.assign_role"):
        raise PermissionDeniedApiException(
            message=f"User '{user.username}' does not have permission assign role.'",
            error_code=ApiErrorCode.PERMISSION_REQUIRED,
        )

    if role == UserRole.ADMIN:
        raise PermissionDeniedApiException(
            message=f"User '{user.username}' does not have permission to assign role admin.'",
            error_code=ApiErrorCode.PERMISSION_REQUIRED,
        )

    if role == UserRole.SUPERVISOR and not user.has_perm("user.assign_supervisor"):
        raise PermissionDeniedApiException(
            message=f"User '{user.username}' does not have permission to assign role supervisor.'",
            error_code=ApiErrorCode.PERMISSION_REQUIRED,
        )


def raise_validation_error(original_error: ValidationError, obj_name: str) -> None:
    errors_list = []

    if hasattr(original_error, "error_dict"):
        for field, field_errors in original_error.error_dict.items():
            for error in field_errors:
                errors_list.append(_create_error_entry(error, field, obj_name))
    elif hasattr(original_error, "error_list") and original_error.error_list != [original_error]:
        errors_list = [_create_error_entry(error) for error in original_error.error_list]
    else:
        errors_list = [_create_error_entry(original_error)]

    raise InvalidDataApiException(
        message=get_error_message_from_error_code(ApiErrorCode.INVALID_VALUES),
        error_data=errors_list,
        error_code=ApiErrorCode.INVALID_VALUES,
    ) from None


def _create_error_entry(error, field=None, obj_name=None):
    error_code = ApiErrorCode(error.code)
    value = error.params.get("value") if error.params else None
    return {
        "field": field,
        "message": get_error_message_from_error_code(error_code, field=field, value=value, obj_name=obj_name),
        "code": error_code.value,
        "value": value,
    }


def raise_does_not_exist_error(obj_name: str, request_data: dict[str, Any]) -> None:
    error_code = ApiErrorCode.OBJECT_NOT_FOUND
    raise ObjectDoesNotExistApiException(
        message=get_error_message_from_error_code(error_code, obj_name=obj_name, **request_data),
        error_data=request_data,
        error_code=error_code,
    ) from None


def raise_unexpected_error(
    method: str, input_data: dict[str, Any] | None, user: User, original_error: Exception
) -> None:
    error_code = ApiErrorCode.UNEXPECTED_ERROR
    raise UnexpectedApiError(
        message=get_error_message_from_error_code(error_code, error=original_error),
        error_data={
            "method": method,
            "input_data": input_data,
            "as_user": user.username,
        },
        error_code=ApiErrorCode.UNEXPECTED_ERROR,
    ) from None


def raise_invalid_token_exception(original_error: Exception) -> None:
    error_code = ApiErrorCode.INVALID_TOKEN
    raise InvalidTokenApiException(
        message=get_error_message_from_error_code(error_code, error=original_error),
        error_data={},
        error_code=error_code,
    ) from None


def get_error_message_from_error_code(error_code: ApiErrorCode, **kwargs) -> str:
    return ERROR_MESSAGES.get(error_code).format(**kwargs)
