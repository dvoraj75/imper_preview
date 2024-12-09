from enum import Enum


class ApiErrorCode(Enum):
    # auth errors
    LOGIN_REQUIRED = "login_required"
    PERMISSION_REQUIRED = "permission_required"
    # lookup errors
    OBJECT_NOT_FOUND = "object_not_found"
    COMPANY_DOES_NOT_EXIST = "company_does_not_exist"
    FIELD_DOES_NOT_EXIST = "field_does_not_exist"
    # validation error codes from django
    INVALID_VALUES = "invalid_values"
    INVALID_VALUE = "invalid"
    INVALID_MAX_LENGTH = "max_length"
    INVALID_MIN_LENGTH = "min_length"
    INVALID_MAX_VALUE = "max_value"
    INVALID_MIN_VALUE = "min_value"
    UNIQUE_ERROR = "unique"
    UNIQUE_TOGETHER_ERROR = "unique_together"
    INVALID_BLANK = "blank"
    INVALID_NULL = "null"
    INVALID_CHOICE = "choice"
    # password validation
    PASSWORD_TOO_COMMON = "password_too_common"  # noqa: S105
    PASSWORD_TOO_SHORT = "password_too_short"  # noqa: S105
    PASSWORD_ENTIRELY_NUMERIC = "password_entirely_numeric"  # noqa: S105
    # other
    UNEXPECTED_ERROR = "unexpected_error"
    # auth
    INVALID_TOKEN = "invalid_token"  # noqa: S105
    INVALID_PASSWORDS = "invalid_passwords"
    INVALID_OLD_PASSWORD = "invalid_old_password"  # noqa: S105

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return super().__eq__(other)
        return self.value == other

    def __hash__(self):
        return super().__hash__()


ERROR_MESSAGES = {
    ApiErrorCode.LOGIN_REQUIRED: "User is unauthorized.",
    ApiErrorCode.PERMISSION_REQUIRED: "User doesn't have required permissions.",
    ApiErrorCode.OBJECT_NOT_FOUND: "{obj_name} with {field} = {value} doesn't exist.",
    ApiErrorCode.COMPANY_DOES_NOT_EXIST: "One or more of the companies doesn't exist.",
    ApiErrorCode.FIELD_DOES_NOT_EXIST: "Field {field} doesn't exist.",
    ApiErrorCode.INVALID_VALUES: "Invalid values.",
    ApiErrorCode.INVALID_VALUE: "Invalid value '{value}' for field '{field}'.",
    ApiErrorCode.INVALID_MAX_LENGTH: "Invalid max length '{max_length}' for field '{field}'.",
    ApiErrorCode.INVALID_MIN_LENGTH: "Invalid min length '{min_length}' for field '{field}'.",
    ApiErrorCode.INVALID_MAX_VALUE: "Invalid max value '{max_value}' for field '{field}'.",
    ApiErrorCode.INVALID_MIN_VALUE: "Invalid min value '{min_value}' for field '{field}'.",
    ApiErrorCode.UNIQUE_ERROR: "{obj_name} with this '{field}' already exist.'",
    ApiErrorCode.UNIQUE_TOGETHER_ERROR: "WIP - some error message",  # TODO
    ApiErrorCode.INVALID_BLANK: "{field} can't be blank.",
    ApiErrorCode.INVALID_NULL: "{field} can't be null.",
    ApiErrorCode.INVALID_CHOICE: "Invalid choice '{value}' for field '{field}'.",
    ApiErrorCode.PASSWORD_TOO_COMMON: "Password is too common.",
    ApiErrorCode.PASSWORD_TOO_SHORT: "Pasword is too short min length is: {min_length}.",
    ApiErrorCode.PASSWORD_ENTIRELY_NUMERIC: "Password is entirely numeric.",
    ApiErrorCode.UNEXPECTED_ERROR: "Unexpected error: {error}",
    ApiErrorCode.INVALID_TOKEN: "Given token is invalid.",
    ApiErrorCode.INVALID_PASSWORDS: "Given passwords are not same.",
    ApiErrorCode.INVALID_OLD_PASSWORD: "Given old password is not valid.",
}
