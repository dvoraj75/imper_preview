from typing import cast
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ValidationError

import pytest
from django_mock_queries.query import MockModel, MockSet
from pytest import FixtureRequest

from evidenta.common.testing.utils import assert_count, assert_equal, assert_none, assert_obj_equal
from evidenta.common.utils import create_url
from evidenta.core.auth.service import AuthService
from evidenta.core.notifications.service import NotificationService
from evidenta.core.user.enums import ResourcePath
from evidenta.core.user.models import CustomUserManager, User
from evidenta.core.user.service import UserService
from evidenta.core.wallet.service import WalletService


SERVICE = UserService()


@pytest.mark.django_db
@pytest.mark.parametrize("user_data,user", [({"data": "some_data"}, "admin")])
def test_user_service_create_should_return_new_user(
    user_data: dict[str, any], user: User, request: FixtureRequest
) -> None:
    user = request.getfixturevalue(user)
    with (
        patch.object(CustomUserManager, "create", return_value=user) as mock_create,
        patch.object(UserService, "invite_user", return_value=None) as mock_invite,
        patch.object(WalletService, "create_wallet", return_value=None) as mock_create_wallet,
    ):
        new_user = SERVICE.create(**user_data)
        mock_create.assert_called_once_with(**user_data)
        mock_invite.assert_called_once_with(user)
        mock_create_wallet.assert_called_once_with(user)
        assert_equal(user, new_user)


@pytest.mark.django_db
@pytest.mark.parametrize("as_user", [(cast(User, "as_user"))])
def test_user_service_get_should_return_user_by_id(as_user: User, user_data: dict[str, any]) -> None:
    mock = MockModel(pk=1, **user_data)
    with patch.object(CustomUserManager, "get_all_related_users", return_value=MockSet(mock)) as mock_get:
        user = SERVICE.get_from_related(as_user=as_user, pk=1)
        mock_get.assert_called_once_with(as_user=as_user)
        assert_obj_equal(cast(User, mock), user)

        mock_get.asset_called_once_with(as_user=as_user)


@pytest.mark.django_db
@pytest.mark.parametrize("as_user", [cast(User, "as_user")])
def test_user_service_get_all_should_return_all_related_users(as_user: User) -> None:
    with patch.object(
        CustomUserManager, "get_all_related_users", return_value=MockSet(MockModel(), MockModel())
    ) as mock_get_all:
        users = SERVICE.get_all_related(as_user=as_user)
        mock_get_all.assert_called_once_with(as_user=as_user)
        assert_count(users, 2)


@pytest.mark.django_db
@pytest.mark.parametrize("as_user,user_data", [("admin", {"data": "some_data"})])
def test_user_service_update_should_return_none_for_successful_update(
    as_user: User, user_data: dict[str, any], request
) -> None:
    user: User = request.getfixturevalue(as_user)
    user_id = "1"
    with (
        patch.object(CustomUserManager, "update", return_value=None) as mock_update,
        patch.object(CustomUserManager, "get", return_value=user) as mock_get,
    ):
        assert_none(SERVICE.update(user_id=user_id, as_user=user, **user_data))
        mock_update.assert_called_once_with(user_id=user_id, as_user=user, **user_data)
        mock_get.assert_called_once_with(pk=user_id)


@pytest.mark.django_db
@pytest.mark.parametrize("as_user", [cast(User, "as_user")])
def test_user_service_delete_should_return_none_for_successful_delete(as_user: User) -> None:
    with patch.object(CustomUserManager, "delete", return_value=None) as mock_update:
        assert_none(SERVICE.delete(user_id=1, as_user=as_user))
        mock_update.assert_called_once_with(user_id=1, as_user=as_user)


@pytest.mark.django_db
@pytest.mark.parametrize("password", ["someLongPassword123"])
def test_set_password_should_successfully_pass(password: str, admin: User) -> None:
    UserService().set_user_password(admin, password)
    assert check_password(password, admin.password)


@pytest.mark.django_db
@pytest.mark.parametrize("password", ["admin", "", "qwerty", "password", "abc"])
def test_set_password_should_should_raise_validation_error_for_invalid_password(password: str, admin: User) -> None:
    with pytest.raises(ValidationError):
        UserService().set_user_password(admin, password)


@pytest.mark.django_db
def test_invite_user_by_email_should_successfully_pass(admin: User, user_mock):
    with (
        patch.object(UserService, "get_from_related", return_value=user_mock) as mock_get,
        patch.object(UserService, "invite_user", return_value=None) as mock_invite,
    ):
        UserService().invite_user_by_email(admin, admin.email)
        mock_get.assert_called_once_with(as_user=admin, email=admin.email)
        mock_invite.assert_called_once_with(user=user_mock)


def test_invite_user_should_successfully_pass(user_mock, valid_token_mock) -> None:
    with (
        patch.object(AuthService, "create_token_for_user", return_value=valid_token_mock) as mock_create,
        patch.object(NotificationService, "send_invitation_link", return_value=None) as mock_send,
    ):
        UserService().invite_user(user_mock)
        mock_create.assert_called_once_with(user_mock, settings.INVITATION_LINK_TOKEN_EXPIRATION_MINS)
        mock_send.assert_called_once_with(
            user=user_mock, link=create_url(settings.FRONTEND_URL, ResourcePath.SETUP_PASSWORD, token=valid_token_mock)
        )


@pytest.mark.django_db
@pytest.mark.parametrize("token,password", [("token_str", "test_password")])
def test_set_password_to_user_by_token_should_successfully_pass(valid_token_mock, user_mock, token, password) -> None:
    with (
        patch.object(AuthService, "get_token", return_value=valid_token_mock) as mock_get,
        patch.object(AuthService, "validate_token", return_value=None) as mock_valid,
        patch.object(UserService, "set_user_password", return_value=None) as mock_set,
        patch.object(AuthService, "delete_token", return_value=None) as mock_delete,
    ):
        UserService().set_password_to_user_by_token(token, password)
        mock_get.assert_called_once_with(token)
        mock_valid.assert_called_once_with(valid_token_mock)
        mock_set.assert_called_once_with(valid_token_mock.user, password)
        mock_delete.assert_called_once_with(valid_token_mock)


@pytest.mark.django_db
@pytest.mark.parametrize("email", ["test@test.cz"])
def test_request_password_change_should_successfully_pass(user_mock, valid_token_mock, email) -> None:
    with (
        patch.object(UserService, "get_from_related", return_value=user_mock) as mock_get,
        patch.object(AuthService, "create_otp_token_for_user", return_value=valid_token_mock) as mock_create,
        patch.object(NotificationService, "send_update_password_otp", return_value=None) as mock_send,
    ):
        UserService().request_password_change(email, user_mock)
        mock_get.assert_called_once_with(as_user=user_mock, email=email)
        mock_create.assert_called_once_with(
            user=user_mock, validity_time=settings.CHANGE_PASSWORD_OTP_TOKEN_EXPIRATION_MINS
        )
        mock_send.assert_called_once_with(user=user_mock, otp=str(valid_token_mock))


@pytest.mark.django_db
@pytest.mark.parametrize("token,password", [("token_str", "test_password")])
def test_change_user_password_by_token_should_successfully_pass(valid_token_mock, user_mock, token, password) -> None:
    with (
        patch.object(AuthService, "get_otp_token", return_value=valid_token_mock) as mock_get,
        patch.object(AuthService, "validate_otp_token", return_value=None) as mock_valid,
        patch.object(UserService, "set_user_password", return_value=None) as mock_set,
        patch.object(AuthService, "delete_token", return_value=None) as mock_delete,
    ):
        UserService().change_user_password_by_token(token, password, user_mock)
        mock_get.assert_called_once_with(token)
        mock_valid.assert_called_once_with(valid_token_mock, user_mock)
        mock_set.assert_called_once_with(valid_token_mock.user, password)
        mock_delete.assert_called_once_with(valid_token_mock)


@pytest.mark.django_db
@pytest.mark.parametrize("email", ["test@test.cz"])
def test_request_password_reset_should_successfully_pass(user_mock, valid_token_mock, email) -> None:
    with (
        patch.object(UserService, "get", return_value=user_mock) as mock_get,
        patch.object(AuthService, "create_token_for_user", return_value=valid_token_mock) as mock_create,
        patch.object(NotificationService, "send_reset_password_link", return_value=None) as mock_send,
    ):
        UserService().request_password_reset(email)
        mock_get.assert_called_once_with(email=email)
        mock_create.assert_called_once_with(user_mock, settings.RESET_PASSWORD_LINK_TOKEN_EXPIRATION_MINS)
        mock_send.assert_called_once_with(
            user=user_mock, link=create_url(settings.FRONTEND_URL, ResourcePath.RESET_PASSWORD, token=valid_token_mock)
        )
