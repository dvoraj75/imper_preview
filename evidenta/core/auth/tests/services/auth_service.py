import secrets
from datetime import timedelta
from unittest.mock import patch

from django.conf import settings
from django.utils import timezone

import pytest
from freezegun import freeze_time

from evidenta.common.testing.utils import assert_none
from evidenta.core.auth.exceptions import InvalidTokenError
from evidenta.core.auth.models import OTPToken, Token
from evidenta.core.auth.service import AuthService


def test_validate_token_return_none_if_token_is_valid(valid_token_mock) -> None:
    assert_none(AuthService().validate_token(valid_token_mock))


def test_validate_token_raise_invalid_token_error_if_token_is_invalid(invalid_token_mock) -> None:
    with pytest.raises(InvalidTokenError):
        AuthService().validate_token(invalid_token_mock)


def test_validate_otp_token_return_none_if_token_is_valid(valid_token_mock, user_mock) -> None:
    assert_none(AuthService().validate_otp_token(valid_token_mock, user_mock))


def test_validate_otp_token_raise_invalid_token_error_if_user_is_invalid(invalid_token_mock, user_mock) -> None:
    with pytest.raises(InvalidTokenError):
        AuthService().validate_otp_token(invalid_token_mock, user_mock)


def test_validate_otp_token_raise_invalid_token_error_if_token_is_invalid(invalid_token_mock, user_mock) -> None:
    invalid_token_mock.user.pk = user_mock.pk
    with pytest.raises(InvalidTokenError):
        AuthService().validate_otp_token(invalid_token_mock, user_mock)


@freeze_time(timezone.now())
@pytest.mark.parametrize("validity_time,token", [(10, "some_token")])
def test_create_token_for_user_should_return_new_token(user_mock, valid_token_mock, validity_time, token) -> None:
    with (
        patch.object(Token.objects, "create", return_value=valid_token_mock) as mock_create,
        patch.object(secrets, "token_urlsafe", return_value=token) as mock_token,
    ):
        AuthService().create_token_for_user(user_mock, validity_time=validity_time)
        mock_create.assert_called_once_with(
            user=user_mock, token=token, expires_at=timezone.now() + timedelta(minutes=validity_time)
        )
        mock_token.assert_called_once_with(settings.DEFAULT_TOKEN_LENGTH)


@freeze_time(timezone.now())
@pytest.mark.parametrize("validity_time,token", [(10, "some_token")])
def test_create_otp_token_for_user_should_return_new_token(user_mock, valid_token_mock, validity_time, token) -> None:
    with (
        patch.object(OTPToken.objects, "create", return_value=valid_token_mock) as mock_create,
        patch.object(AuthService, "_generate_otp_token", return_value=token) as mock_token,
    ):
        AuthService().create_otp_token_for_user(user_mock, validity_time=validity_time)
        mock_create.assert_called_once_with(
            user=user_mock, token=token, expires_at=timezone.now() + timedelta(minutes=validity_time)
        )
        mock_token.assert_called_once_with(settings.DEFAULT_OTP_TOKEN_LENGTH)


@pytest.mark.parametrize("token", ["some_token"])
def test_get_token_should_return_token(valid_token_mock, token) -> None:
    with patch.object(Token.objects, "get", return_value=valid_token_mock) as mock_token:
        AuthService().get_token(token)
        mock_token.assert_called_once_with(token=token)


@pytest.mark.parametrize("token", ["some_token"])
def test_get_otp_token_should_return_token(valid_token_mock, token) -> None:
    with patch.object(OTPToken.objects, "get", return_value=valid_token_mock) as mock_token:
        AuthService().get_otp_token(token)
        mock_token.assert_called_once_with(token=token)


def test_delete_token_should_pass(valid_token_mock) -> None:
    with patch.object(AuthService, "delete_token", return_value=None) as mock_delete:
        AuthService().delete_token(valid_token_mock)
        mock_delete.assert_called_once_with(valid_token_mock)
