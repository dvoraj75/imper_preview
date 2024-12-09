from unittest.mock import patch

from django.core.exceptions import ObjectDoesNotExist, ValidationError

import pytest
from graphene_django.utils.testing import graphql_query

from evidenta.common.enums import ApiErrorCode
from evidenta.common.testing.utils import assert_equal, assert_error_code, assert_exist
from evidenta.core.auth import schema
from evidenta.core.auth.exceptions import InvalidTokenError
from evidenta.core.user.service import UserService


@pytest.mark.django_db
@pytest.mark.parametrize(
    "mutation_query",
    [
        {
            "mutation": "changePassword",
            "input": {
                "token": "123456",
                "oldPassword": "old_test",
                "newPassword": "test",
                "newPasswordConfirm": "test",
            },
        }
    ],
    indirect=True,
)
def test_change_password_should_successfully_pass(django_client, admin, mutation_query, valid_token_mock) -> None:
    django_client.force_login(admin)
    with (
        patch.object(schema, "check_password", return_value=True) as mock_check,
        patch.object(UserService, "change_user_password_by_token", return_value=None) as mock_change,
    ):
        response = graphql_query(mutation_query, client=django_client)
        assert_equal(response.status_code, 200)
        mock_check.assert_called_once_with("old_test", admin.password)
        mock_change.assert_called_once_with("123456", "test", admin)
        assert_exist(response.json().get("data"))


@pytest.mark.django_db
@pytest.mark.parametrize(
    "mutation_query",
    [
        {
            "mutation": "changePassword",
            "input": {
                "token": "123456",
                "oldPassword": "old_test",
                "newPassword": "test",
                "newPasswordConfirm": "test",
            },
        }
    ],
    indirect=True,
)
def test_change_password_should_raise_invalid_data_api_exception_for_invalid_old_password(
    django_client, admin, mutation_query, valid_token_mock
) -> None:
    django_client.force_login(admin)
    with patch.object(schema, "check_password", return_value=False) as mock_check_password:
        response = graphql_query(mutation_query, client=django_client)
        assert_equal(response.status_code, 400)
        mock_check_password.assert_called_once_with("old_test", admin.password)
        assert_error_code(response.json(), ApiErrorCode.INVALID_OLD_PASSWORD)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "mutation_query",
    [
        {
            "mutation": "changePassword",
            "input": {
                "token": "123456",
                "oldPassword": "old_test",
                "newPassword": "test_invalid",
                "newPasswordConfirm": "test",
            },
        }
    ],
    indirect=True,
)
def test_change_password_should_raise_invalid_data_api_exception_for_different_passwords(
    django_client, admin, mutation_query, valid_token_mock
) -> None:
    django_client.force_login(admin)
    with patch.object(schema, "check_password", return_value=True) as mock_check_password:
        response = graphql_query(mutation_query, client=django_client)
        assert_equal(response.status_code, 400)
        mock_check_password.assert_called_once_with("old_test", admin.password)
        assert_error_code(response.json(), ApiErrorCode.INVALID_PASSWORDS)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "mutation_query",
    [
        {
            "mutation": "changePassword",
            "input": {
                "token": "123456",
                "oldPassword": "old_test",
                "newPassword": "test",
                "newPasswordConfirm": "test",
            },
        }
    ],
    indirect=True,
)
@pytest.mark.parametrize(
    "raising,expected_code",
    [
        (ObjectDoesNotExist("Object does not exist"), ApiErrorCode.OBJECT_NOT_FOUND),
        (InvalidTokenError("Some error", code=ApiErrorCode.INVALID_TOKEN), ApiErrorCode.INVALID_TOKEN),
        (ValidationError("Some val error", code=ApiErrorCode.PASSWORD_TOO_COMMON), ApiErrorCode.INVALID_VALUES),
        (ValueError("Some err"), ApiErrorCode.UNEXPECTED_ERROR),
    ],
)
def test_change_password_should_correctly_react_on_exceptions(
    django_client, admin, mutation_query, valid_token_mock, raising, expected_code
) -> None:
    django_client.force_login(admin)
    with (
        patch.object(schema, "check_password", return_value=True) as mock_check_password,
        patch.object(UserService, "change_user_password_by_token", side_effect=raising) as mock_change,
    ):
        response = graphql_query(mutation_query, client=django_client)
        assert_equal(response.status_code, 400)
        mock_check_password.assert_called_once_with("old_test", admin.password)
        mock_change.assert_called_once_with("123456", "test", admin)
        assert_error_code(response.json(), expected_code)
