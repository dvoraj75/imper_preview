from unittest.mock import patch

from django.core.exceptions import ObjectDoesNotExist

import pytest
from graphene_django.utils.testing import graphql_query

from evidenta.common.enums import ApiErrorCode
from evidenta.common.testing.utils import assert_equal, assert_error_code, assert_exist
from evidenta.core.user.service import UserService


@pytest.mark.django_db
@pytest.mark.parametrize(
    "mutation_query",
    [{"mutation": "sendChangePasswordOtpToken", "input": {"email": "test@test.cz"}}],
    indirect=True,
)
def test_send_user_otp_token_should_successfully_pass(mutation_query, user_mock, django_client, admin) -> None:
    django_client.force_login(admin)
    with patch.object(UserService, "request_password_change", return_value=None) as mock_request:
        response = graphql_query(mutation_query, client=django_client)
        assert_equal(response.status_code, 200)
        mock_request.assert_called_once_with(email="test@test.cz", as_user=admin)
        assert_exist(response.json().get("data"))


@pytest.mark.django_db
@pytest.mark.parametrize(
    "mutation_query",
    [{"mutation": "sendChangePasswordOtpToken", "input": {"email": "test@test.cz"}}],
    indirect=True,
)
@pytest.mark.parametrize(
    "raising,expected_code",
    [
        (ObjectDoesNotExist("Object does not exist"), ApiErrorCode.OBJECT_NOT_FOUND),
        (ValueError("Some err"), ApiErrorCode.UNEXPECTED_ERROR),
    ],
)
def test_send_user_otp_token_should_correctly_react_on_exceptions(
    mutation_query, django_client, admin, raising, expected_code
) -> None:
    django_client.force_login(admin)
    with patch.object(UserService, "get_from_related", side_effect=raising) as mock_get:
        response = graphql_query(mutation_query, client=django_client)
        assert_equal(response.status_code, 400)
        mock_get.assert_called_once_with(email="test@test.cz", as_user=admin)
        assert_error_code(response.json(), expected_code)
