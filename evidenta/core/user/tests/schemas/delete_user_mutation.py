from unittest.mock import patch

from django.test import Client

import pytest
from graphene_django.utils.testing import graphql_query

from evidenta.common.enums import ApiErrorCode
from evidenta.common.testing.utils import assert_equal, assert_error_code, assert_exist
from evidenta.core.user.models import User
from evidenta.core.user.service import UserService


@pytest.mark.django_db
def test_delete_user_mutation_should_successfully_pass(
    django_client: Client, admin: User, mock_function_create_or_update, delete_user_mutation_query
) -> None:
    django_client.force_login(admin)
    with patch.object(UserService, "delete", mock_function_create_or_update):
        response = graphql_query(delete_user_mutation_query, client=django_client)
        assert_equal(response.status_code, 200)
        assert_exist(response.json().get("data"))


@pytest.mark.django_db
def test_delete_user_mutation_should_raise_object_does_not_exist_api_exception_for_non_existing_user(
    django_client: Client, admin: User, mock_function_create_or_update, delete_user_mutation_query
):
    django_client.force_login(admin)
    with patch.object(UserService, "delete", side_effect=User.DoesNotExist):
        response = graphql_query(delete_user_mutation_query, client=django_client)
        assert_equal(response.status_code, 400)
        assert_error_code(response.json(), ApiErrorCode.OBJECT_NOT_FOUND)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "error", [ValueError("Some value error"), TypeError("Some type error"), KeyError("Some key error")]
)
def test_delete_user_mutation_should_raise_unexpected_api_error_when_except_random_error(
    django_client: Client, admin: User, delete_user_mutation_query, error
) -> None:
    django_client.force_login(admin)
    with patch.object(UserService, "delete", side_effect=error):
        response = graphql_query(delete_user_mutation_query, client=django_client)
        assert_equal(response.status_code, 400)
        assert_exist(response.json().get("errors"))
        assert_error_code(response.json(), ApiErrorCode.UNEXPECTED_ERROR)
