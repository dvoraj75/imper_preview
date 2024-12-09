from unittest.mock import patch

from django.core.exceptions import ObjectDoesNotExist, ValidationError

import pytest
from graphene_django.utils.testing import graphql_query

from evidenta.common.enums import ApiErrorCode
from evidenta.common.testing.utils import assert_equal, assert_error_code, assert_exist
from evidenta.core.auth.exceptions import InvalidTokenError
from evidenta.core.user.service import UserService


@pytest.mark.parametrize(
    "mutation_query",
    [
        {
            "mutation": "setPassword",
            "input": {"token": "123456", "password": "test", "passwordConfirm": "test"},
        }
    ],
    indirect=True,
)
def test_set_password_should_successfully_pass(mutation_query, valid_token_mock) -> None:
    with patch.object(UserService, "set_password_to_user_by_token", return_value=None) as mock_set:
        response = graphql_query(mutation_query)
        assert_equal(response.status_code, 200)
        mock_set.assert_called_once_with("123456", "test")
        assert_exist(response.json().get("data"))


@pytest.mark.parametrize(
    "mutation_query",
    [
        {
            "mutation": "setPassword",
            "input": {"token": "123456", "password": "test", "passwordConfirm": "testtest"},
        }
    ],
    indirect=True,
)
def test_set_password_should_raise_invalid_data_api_exception_for_different_passwords(
    mutation_query, valid_token_mock
) -> None:
    response = graphql_query(mutation_query)
    assert_equal(response.status_code, 400)
    assert_error_code(response.json(), ApiErrorCode.INVALID_PASSWORDS)


@pytest.mark.parametrize(
    "mutation_query",
    [
        {
            "mutation": "setPassword",
            "input": {"token": "123456", "password": "test", "passwordConfirm": "test"},
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
def test_set_password_should_correctly_react_on_exceptions(mutation_query, raising, expected_code) -> None:
    with patch.object(UserService, "set_password_to_user_by_token", side_effect=raising) as mock_get:
        response = graphql_query(mutation_query)
        assert_equal(response.status_code, 400)
        mock_get.assert_called_once_with("123456", "test")
        assert_error_code(response.json(), expected_code)
