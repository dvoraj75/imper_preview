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
    [{"mutation": "sendInvitationLink", "input": {"email": "test@test.cz"}}],
    indirect=True,
)
def test_send_user_invitation_link_should_successfully_pass(mutation_query, user_mock, django_client, admin) -> None:
    django_client.force_login(admin)
    with patch.object(UserService, "invite_user_by_email", return_value=None) as mock_invite:
        response = graphql_query(mutation_query, client=django_client)
        assert_equal(response.status_code, 200)
        mock_invite.assert_called_once_with(as_user=admin, email="test@test.cz")
        assert_exist(response.json().get("data"))


@pytest.mark.django_db
@pytest.mark.parametrize(
    "mutation_query",
    [{"mutation": "sendInvitationLink", "input": {"email": "test@test.cz"}}],
    indirect=True,
)
@pytest.mark.parametrize(
    "raising,expected_code",
    [
        (ObjectDoesNotExist("Object does not exist"), ApiErrorCode.OBJECT_NOT_FOUND),
        (ValueError("value error"), ApiErrorCode.UNEXPECTED_ERROR),
    ],
)
def test_send_user_invitation_link_should_correctly_react_on_exceptions(
    mutation_query, django_client, admin, raising, expected_code
) -> None:
    django_client.force_login(admin)
    with patch.object(UserService, "invite_user_by_email", side_effect=raising) as mock_invite:
        response = graphql_query(mutation_query, client=django_client)
        assert_equal(response.status_code, 400)
        mock_invite.assert_called_once_with(as_user=admin, email="test@test.cz")
        assert_error_code(response.json(), expected_code)
