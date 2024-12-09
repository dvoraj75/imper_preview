import unittest.mock
from unittest.mock import patch

from django.core.exceptions import PermissionDenied, ValidationError

import pytest
from pytest import FixtureRequest

from evidenta.core.wallet.models import Wallet, WalletManager, WalletRecord
from evidenta.core.wallet.service import WalletService


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_wallet_service_create_wallet(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    with patch.object(WalletManager, "create_wallet", return_value=user.wallet) as mock_create_wallet:
        wallet = WalletService().create_wallet(user)
        mock_create_wallet.assert_called_once_with(user)
        assert wallet == user.wallet
        assert isinstance(wallet, Wallet)


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_wallet_service_recreate_wallet(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    with pytest.raises(ValidationError):
        WalletService().create_wallet(user)


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_wallet_service_create_record(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    record_data = {
        "name": "name",
        "username": "username",
        "secret": "secret",
        "description": "test-description",
    }
    ret_value = unittest.mock.Mock()
    with patch.object(WalletManager, "create_record", return_value=ret_value) as mock_create_wallet:
        record = WalletService().create_record(user, **record_data)
        mock_create_wallet.assert_called_once_with(user, **record_data)
        assert record == ret_value


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_wallet_service_update_record__success(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    record_data = {
        "name": "name",
        "username": "username",
        "secret": "secret",
        "description": "test-description",
    }
    ret_value = unittest.mock.Mock()
    record_id = "123"
    with patch.object(WalletManager, "update_record", return_value=ret_value) as mock_create_wallet:
        record = WalletService().update_record(user, record_id, **record_data)
        mock_create_wallet.assert_called_once_with(user, record_id, **record_data)
        assert record == ret_value


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_wallet_service_update_record__fail(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    record_data = {
        "name": "name",
        "username": "username",
        "secret": "secret",
        "description": "test-description",
    }
    record_id = "123"
    with pytest.raises(WalletRecord.DoesNotExist):
        WalletService().update_record(user, record_id, **record_data)


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_wallet_service_change_password(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    old_password = "old-password"  # noqa:S105
    with patch.object(WalletManager, "change_password") as mock_change_password:
        WalletService().change_password(user, old_password)
        mock_change_password.assert_called_once_with(user, old_password)


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_wallet_service_delete_record__success(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    ret_value = unittest.mock.Mock()
    record_id = "123"
    with patch.object(WalletManager, "delete_record", return_value=ret_value) as mock_delete_record:
        record = WalletService().delete_record(user, record_id)
        mock_delete_record.assert_called_once_with(user, record_id)
        assert record == ret_value


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_wallet_service_delete_record__fail(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    record_id = "123"
    with pytest.raises(WalletRecord.DoesNotExist):
        WalletService().delete_record(user, record_id)


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_wallet_service_get_records(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    number_of_records = 10
    ret_value = [unittest.mock.Mock() for _ in range(number_of_records)]
    with patch.object(WalletManager, "get_records", return_value=ret_value) as mock_get_records:
        records = WalletService().get_records(user)
        mock_get_records.assert_called_once_with(user)
        assert records == ret_value


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_wallet_service_get_record__success(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    ret_value = unittest.mock.Mock()
    record_id = "123"
    with patch.object(WalletManager, "get_record", return_value=ret_value) as mock_get_record:
        record = WalletService().get_record(user, record_id)
        mock_get_record.assert_called_once_with(user, record_id)
        assert record == ret_value


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_wallet_service_get_record__fail(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    record_id = "123"
    with pytest.raises(WalletRecord.DoesNotExist):
        WalletService().get_record(user, record_id)


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_wallet_service_unlock_wallet(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    with pytest.raises(PermissionDenied):
        WalletService().unlock_wallet(user, "bad-password")
