from unittest.mock import patch

from django.test import Client

import pytest
from graphene_django.utils.testing import graphql_query

from evidenta.common.enums import ERROR_MESSAGES, ApiErrorCode
from evidenta.common.testing.utils import (
    assert_equal,
    assert_error_code,
    assert_error_message,
    assert_exist,
    assert_match_error_message,
)
from evidenta.core.user.enums import UserRole
from evidenta.core.user.models import User
from evidenta.core.user.service import UserService


@pytest.mark.django_db
def test_create_user_mutation_should_return_user(
    django_client: Client, admin: User, mock_function_create_or_update, create_user_mutation_query
) -> None:
    django_client.force_login(admin)
    with patch.object(UserService, "create", mock_function_create_or_update):
        response = graphql_query(create_user_mutation_query, client=django_client)
        assert_equal(response.status_code, 200)
        assert_exist(response.json().get("data"))


@pytest.mark.django_db
def test_create_user_mutation_should_raise_invalid_data_api_exception_when_except_validation_error(
    django_client: Client, admin: User, mock_function_invalid_data_error, create_user_mutation_query
) -> None:
    django_client.force_login(admin)
    with patch.object(UserService, "create", mock_function_invalid_data_error):
        response = graphql_query(create_user_mutation_query, client=django_client)
        assert_equal(response.status_code, 400)
        assert_exist(response.json().get("errors"))
        assert_equal(
            response.json().get("errors")[0].get("error_data")[0].get("code"),
            ApiErrorCode.INVALID_VALUES.value,
        )
        assert_equal(
            response.json().get("errors")[0].get("error_data")[0].get("message"),
            ERROR_MESSAGES[ApiErrorCode.INVALID_VALUES],
        )


@pytest.mark.django_db
@pytest.mark.parametrize(
    "error", [ValueError("Some value error"), TypeError("Some type error"), KeyError("Some key error")]
)
def test_create_user_mutation_should_raise_unexpected_api_error_when_except_random_error(
    django_client: Client, admin: User, create_user_mutation_query, error
) -> None:
    django_client.force_login(admin)
    with patch.object(UserService, "create", side_effect=error):
        response = graphql_query(create_user_mutation_query, client=django_client)
        assert_equal(response.status_code, 400)
        assert_exist(response.json().get("errors"))
        assert_error_message(response.json(), ApiErrorCode.UNEXPECTED_ERROR, error)


@pytest.mark.parametrize(
    "create_user_mutation_query",
    [
        {"exclude": ("username",)},
        {"exclude": ("firstName",)},
        {"exclude": ("lastName",)},
        {"exclude": ("email",)},
        {"exclude": ("role",)},
    ],
    indirect=True,
)
def test_create_user_mutation_should_fail_when_missing_required_field(
    django_client, create_user_mutation_query
) -> None:
    response = graphql_query(create_user_mutation_query)
    assert_equal(response.status_code, 400)
    assert_exist(response.json().get("errors"))
    assert_match_error_message(response.json(), r"^Field.+not provided.$")


@pytest.mark.parametrize(
    "create_user_mutation_query",
    [
        {"extra": {"vyska": 130}},
        {"extra": {"pocet": "nekolik"}},
    ],
    indirect=True,
)
def test_create_user_mutation_should_fail_when_get_unknown_field(django_client, create_user_mutation_query) -> None:
    response = graphql_query(create_user_mutation_query)
    assert_equal(response.status_code, 400)
    assert_exist(response.json().get("errors"))
    assert_match_error_message(response.json(), r"^Field.+not defined.+$")


@pytest.mark.django_db
@pytest.mark.parametrize(
    "create_user_mutation_query",
    [
        {"extra": {"companies": [1, 2, 3]}},
    ],
    indirect=True,
)
def test_create_user_mutation_should_fail_with_permission_denied_if_user_without_permissions_set_companies(
    django_client,
    guest,
    create_user_mutation_query,
) -> None:
    guest.add_permission("add_user")
    django_client.force_login(guest)
    response = graphql_query(create_user_mutation_query, client=django_client)
    assert_equal(response.status_code, 400)
    assert_exist(response.json().get("errors"))
    assert_error_code(response.json(), ApiErrorCode.PERMISSION_REQUIRED)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "create_user_mutation_query",
    [
        {"extra": {"role": UserRole.GUEST}},
    ],
    indirect=True,
)
def test_create_user_mutation_should_fail_with_permission_denied_if_user_without_permissions_set_role(
    django_client,
    guest,
    create_user_mutation_query,
) -> None:
    guest.add_permission("add_user")
    django_client.force_login(guest)
    response = graphql_query(create_user_mutation_query, client=django_client)
    assert_equal(response.status_code, 400)
    assert_exist(response.json().get("errors"))
    assert_error_code(response.json(), ApiErrorCode.PERMISSION_REQUIRED)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "create_user_mutation_query",
    [
        {"extra": {"role": UserRole.SUPERVISOR}},
    ],
    indirect=True,
)
def test_create_user_mutation_should_fail_with_permission_denied_if_user_without_permissions_set_supervisor_role(
    django_client,
    guest,
    create_user_mutation_query,
) -> None:
    guest.add_permission("add_user")
    guest.add_permission("assign_role")
    django_client.force_login(guest)
    response = graphql_query(create_user_mutation_query, client=django_client)
    assert_equal(response.status_code, 400)
    assert_exist(response.json().get("errors"))
    assert_error_code(response.json(), ApiErrorCode.PERMISSION_REQUIRED)
