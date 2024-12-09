from unittest.mock import MagicMock, patch

from django.test import Client

import pytest
from graphene_django.utils.testing import graphql_query

from evidenta.common.enums import ApiErrorCode
from evidenta.common.testing.utils import (
    assert_equal,
    assert_obj_equal,
    extract_error_code_from_graphql_error_response,
    extract_message_from_graphql_error_response,
    generate_all_query,
    generate_query,
)
from evidenta.core.user.models import User
from evidenta.core.user.schemas import MeQuery, UserNode
from evidenta.core.user.service import UserService


@pytest.mark.django_db
def test_get_queryset_should_not_fail_when_user_is_logged_and_has_permission(
    admin: User, django_client: Client, empty_filter_mock: MagicMock
) -> None:
    django_client.force_login(admin)
    with patch.object(UserService, "get_all_related", return_value=empty_filter_mock):
        info = MagicMock()
        info.context.user = admin
        UserNode.get_queryset(None, info)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "exception,message", [(ValueError, "ValueError"), (AttributeError, "AttributeError"), (TypeError, "TypeError")]
)
def test_get_queryset_should_raise_unexpected_api_error(
    admin: User, django_client: Client, exception: type[Exception], message: str
) -> None:
    query = generate_all_query("users", ["id"])
    django_client.force_login(admin)
    with patch.object(UserService, "get_all_related", side_effect=exception(message)):
        response = graphql_query(query, client=django_client)
        assert_equal(response.status_code, 400)
        assert_equal(
            extract_message_from_graphql_error_response(response.json()),
            f"Unexpected error: {message}",
        )
        assert_equal(
            extract_error_code_from_graphql_error_response(response.json()), ApiErrorCode.UNEXPECTED_ERROR.value
        )


def test_get_queryset_should_fail_with_permission_denied_when_user_is_not_logged_in(django_client: Client) -> None:
    query = generate_all_query("users", ["id"])
    response = graphql_query(query, client=django_client)
    assert_equal(response.status_code, 400)
    assert_equal(extract_error_code_from_graphql_error_response(response.json()), ApiErrorCode.LOGIN_REQUIRED.value)


@pytest.mark.django_db
def test_get_queryset_should_fail_with_permission_denied_when_user_doesnt_have_permissions(
    guest: User, django_client: Client
) -> None:
    django_client.force_login(guest)
    query = generate_all_query("users", ["id"])
    response = graphql_query(query, client=django_client)
    assert_equal(response.status_code, 400)
    assert_equal(
        extract_error_code_from_graphql_error_response(response.json()), ApiErrorCode.PERMISSION_REQUIRED.value
    )


@pytest.mark.parametrize("field", ["password", "test", "some_field"])
def test_get_queryset_should_fail_with_graphql_error_for_non_existing_fields(field: str) -> None:
    query = generate_all_query("users", ["id", field])
    response = graphql_query(query)
    assert_equal(response.status_code, 400)
    assert_equal(
        f"Cannot query field '{field}' on type 'UserNode'.",
        extract_message_from_graphql_error_response(response.json()),
    )


@pytest.mark.django_db
def test_get_node_should_not_fail_when_user_is_logged_and_has_permission(
    admin: User, django_client: Client, empty_filter_mock: MagicMock
) -> None:
    django_client.force_login(admin)
    with patch.object(UserService, "get_from_related", return_value=empty_filter_mock):
        info = MagicMock()
        info.context.user = admin
        UserNode.get_node(info, "1")


@pytest.mark.django_db
@pytest.mark.parametrize(
    "exception,message", [(ValueError, "ValueError"), (AttributeError, "AttributeError"), (TypeError, "TypeError")]
)
def test_get_node_should_raise_unexpected_api_error(
    admin: User, django_client: Client, exception: type[Exception], message: str
) -> None:
    query = generate_query("user", ["username"], id="VXNlck5vZGU6Ng==")
    django_client.force_login(admin)
    with patch.object(UserService, "get_from_related", side_effect=exception(message)):
        response = graphql_query(query, client=django_client)
        assert_equal(response.status_code, 400)
        assert_equal(
            extract_message_from_graphql_error_response(response.json()),
            f"Unexpected error: {message}",
        )
        assert_equal(
            extract_error_code_from_graphql_error_response(response.json()), ApiErrorCode.UNEXPECTED_ERROR.value
        )


@pytest.mark.django_db
def test_get_node_should_raise_object_does_not_exist_error(admin: User, django_client: Client) -> None:
    query = generate_query("user", ["username"], id="VXNlck5vZGU6Ng==")
    django_client.force_login(admin)
    with patch.object(UserService, "get_from_related", side_effect=User.DoesNotExist):
        response = graphql_query(query, client=django_client)
        assert_equal(response.status_code, 400)
        assert_equal(
            extract_error_code_from_graphql_error_response(response.json()), ApiErrorCode.OBJECT_NOT_FOUND.value
        )


def test_get_node_should_fail_with_permission_denied_when_user_is_not_logged_in(django_client: Client) -> None:
    query = generate_query("user", ["username"], id="VXNlck5vZGU6Ng==")
    response = graphql_query(query, client=django_client)
    assert_equal(response.status_code, 400)
    assert_equal(extract_error_code_from_graphql_error_response(response.json()), ApiErrorCode.LOGIN_REQUIRED.value)


@pytest.mark.django_db
def test_get_node_should_fail_with_permission_denied_when_user_doesnt_have_permissions(
    guest: User, django_client: Client
) -> None:
    django_client.force_login(guest)
    query = generate_query("user", ["username"], id="VXNlck5vZGU6Ng==")
    response = graphql_query(query, client=django_client)
    assert_equal(response.status_code, 400)
    assert_equal(
        extract_error_code_from_graphql_error_response(response.json()), ApiErrorCode.PERMISSION_REQUIRED.value
    )


@pytest.mark.parametrize("field", ["password", "test", "some_field"])
def test_get_node_should_fail_with_graphql_error_for_non_existing_fields(field: str) -> None:
    query = generate_query("user", ["username", field], id="VXNlck5vZGU6Ng==")
    response = graphql_query(query)
    assert_equal(response.status_code, 400)
    assert_equal(
        f"Cannot query field '{field}' on type 'UserNode'.",
        extract_message_from_graphql_error_response(response.json()),
    )


@pytest.mark.django_db
def test_resolve_me_should_return_current_user(
    admin: User, django_client: Client, empty_filter_mock: MagicMock
) -> None:
    django_client.force_login(admin)
    with patch.object(UserService, "get_all_related", return_value=empty_filter_mock):
        info = MagicMock()
        info.context.user = admin
        assert_obj_equal(MeQuery.resolve_me(None, info), admin)


def test_resolve_me_should_fail_with_permission_denied_when_user_is_not_logged_in(django_client: Client) -> None:
    query = """
    {
      me {
        username
      }
    }
    """
    response = graphql_query(query, client=django_client)
    assert_equal(response.status_code, 400)
    assert_equal(extract_error_code_from_graphql_error_response(response.json()), ApiErrorCode.LOGIN_REQUIRED.value)


@pytest.mark.parametrize("field", ["password", "test", "some_field"])
def test_resolve_me_should_fail_with_graphql_error_for_non_existing_fields(field: str) -> None:
    query = """
    {{
      me  {{
        username,
        {field}
      }}
    }}
    """.format(
        field=field
    )
    response = graphql_query(query)
    assert_equal(response.status_code, 400)
    assert_equal(
        f"Cannot query field '{field}' on type 'UserNode'.",
        extract_message_from_graphql_error_response(response.json()),
    )
