from unittest.mock import patch

from django.core.exceptions import ObjectDoesNotExist

import pytest
from graphene_django.utils.testing import graphql_query

from evidenta.common.enums import ApiErrorCode
from evidenta.common.testing.utils import assert_equal, assert_error_code, assert_exist
from evidenta.core.user.service import UserService


@pytest.mark.parametrize(
    "mutation_query",
    [{"mutation": "sendResetPasswordLink", "input": {"email": "test@test.cz"}}],
    indirect=True,
)
def test_send_reset_password_link_should_successfully_pass(mutation_query, user_mock) -> None:
    with patch.object(UserService, "request_password_reset", return_value=user_mock) as mock_request:
        response = graphql_query(mutation_query)
        assert_equal(response.status_code, 200)
        mock_request.assert_called_once_with(email="test@test.cz")
        assert_exist(response.json().get("data"))


@pytest.mark.parametrize(
    "mutation_query",
    [{"mutation": "sendResetPasswordLink", "input": {"email": "test@test.cz"}}],
    indirect=True,
)
@pytest.mark.parametrize(
    "error",
    [
        (ObjectDoesNotExist("some error"), ApiErrorCode.UNEXPECTED_ERROR),
    ],
)
def test_send_reset_password_link_should_successfully_pass_on_object_does_not_exist_error(
    mutation_query, error
) -> None:
    with patch.object(UserService, "request_password_reset", side_effect=error) as mock_request:
        response = graphql_query(mutation_query)
        assert_equal(response.status_code, 200)
        mock_request.assert_called_once_with(email="test@test.cz")
        assert_exist(response.json().get("data"))


@pytest.mark.parametrize(
    "mutation_query",
    [{"mutation": "sendResetPasswordLink", "input": {"email": "test@test.cz"}}],
    indirect=True,
)
@pytest.mark.parametrize(
    "raising,expected_code",
    [
        (ValueError("value error"), ApiErrorCode.UNEXPECTED_ERROR),
    ],
)
def test_send_reset_password_link_should_correctly_react_on_exceptions(mutation_query, raising, expected_code) -> None:
    with patch.object(UserService, "request_password_reset", side_effect=raising) as mock_request:
        response = graphql_query(mutation_query)
        assert_equal(response.status_code, 400)
        mock_request.assert_called_once_with(email="test@test.cz")
        assert_error_code(response.json(), expected_code)
