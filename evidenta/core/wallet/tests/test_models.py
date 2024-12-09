import re
from typing import Any

from django.core.exceptions import ValidationError

import pytest
from pytest import FixtureRequest

from evidenta.core.user.enums import UserRole
from evidenta.core.user.models import User
from evidenta.core.wallet.models import Wallet, WalletRecord


def _create_user(**user_data) -> User:
    return User.objects.create(**user_data)


def _create_record(
    user: User,
    name: str = "test",
    username: str = "username",
    secret: str = "secret",  # noqa: S107
    description: str = "test description",
) -> WalletRecord:
    return Wallet.objects.create_record(user, name=name, username=username, secret=secret, description=description)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "user_data", [{"role": role} for role in UserRole if role not in (UserRole.GUEST, UserRole.CLIENT)], indirect=True
)
def test_wallet_creation_all_users(user_data: dict[str, Any]) -> None:
    user = _create_user(**user_data)
    wallet = Wallet.objects.create_wallet(user=user)
    # Check if wallet was created
    assert Wallet.objects.count() == 1
    assert user.wallet == wallet
    # Check wallet is empty
    assert WalletRecord.objects.count() == 0


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_create_record_all_users(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    assert WalletRecord.objects.count() == 0
    record = _create_record(user)
    assert WalletRecord.objects.count() == 1
    assert user.wallet.walletrecord_set.get(pk=record.pk) == record


@pytest.mark.django_db
def test_wallet_creation_multiple_users(request: FixtureRequest) -> None:
    admin_data = request.getfixturevalue("user_data")
    admin_data.update({"username": "test-admin", "email": "test@admin.cz"})
    admin = _create_user(**admin_data)
    accountant_data = request.getfixturevalue("user_data")
    accountant_data.update({"username": "test-accountant", "email": "accountant@test.cz"})
    accountant = _create_user(**accountant_data)
    wallet_admin = Wallet.objects.create_wallet(user=admin)
    wallet_accountant = Wallet.objects.create_wallet(user=accountant)
    assert WalletRecord.objects.count() == 0
    assert Wallet.objects.count() == 2
    assert admin.wallet == wallet_admin
    assert accountant.wallet == wallet_accountant
    assert admin.wallet != accountant.wallet


@pytest.mark.django_db
def test_wallet_record_creation_multiple_users_and_records(request: FixtureRequest) -> None:
    admin_data = request.getfixturevalue("user_data")
    admin_data.update({"username": "test-admin", "email": "test@admin.cz"})
    admin = _create_user(**admin_data)
    accountant_data = request.getfixturevalue("user_data")
    accountant_data.update({"username": "test-accountant", "email": "accountant@test.cz"})
    accountant = _create_user(**accountant_data)
    wallet_admin = Wallet.objects.create_wallet(user=admin)
    wallet_accountant = Wallet.objects.create_wallet(user=accountant)
    assert WalletRecord.objects.count() == 0
    record = _create_record(accountant)
    assert WalletRecord.objects.count() == 1
    assert accountant.wallet.walletrecord_set.get(pk=record.pk) == record
    assert not admin.wallet.walletrecord_set.filter(pk=record.pk).exists()
    assert admin.wallet == wallet_admin
    assert accountant.wallet == wallet_accountant


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_create_wallet__long_salt(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    with pytest.raises(ValidationError, match="Ensure this value has at most 32 characters"):
        Wallet.objects.create(user=user, salt="some salt" * 32)


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_create_wallet__existing_user(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    with pytest.raises(ValidationError, match="Wallet with this User already exists."):
        Wallet.objects.create_wallet(user=user)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "record_data",
    [
        {
            "name": "test" * 255,
            "username": "username",
            "secret": "secret",
            "description": "description",
            "nonce": "some nonce",
        },
        {
            "name": "test",
            "username": "username" * 255,
            "secret": "secret",
            "description": "description",
            "nonce": "some nonce",
        },
        {
            "name": "test",
            "username": "username",
            "secret": "secret" * 255,
            "description": "description",
            "nonce": "some nonce",
        },
        {
            "name": "test",
            "username": "username",
            "secret": "secret",
            "description": "description",
            "nonce": "some nonce" * 64,
        },
    ],
)
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_create_wallet_record__long_field_values(
    record_data: dict[str, str], user_fixture: str, request: FixtureRequest
) -> None:
    user = request.getfixturevalue(user_fixture)
    with pytest.raises(ValidationError, match=re.compile(r"Ensure this value has at most \d+ characters.")):
        WalletRecord.objects.create(wallet=user.wallet, **record_data)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "field, value",
    [
        ("name", "test"),
        ("username", "test"),
        ("secret", "secret"),
        ("description", "description"),
    ],
)
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_update_wallet_record__successful(field: str, value: str, user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    record = _create_record(
        user, name="something", username="different", secret="from", description="parametrize"  # noqa: S106
    )
    updated = Wallet.objects.update_record(user=user, record_id=record.pk, **{field: value})
    assert record.pk == updated.pk
    if field == "secret":
        assert Wallet.objects.get_decrypted_record_secret(user, updated) == value
    else:
        assert getattr(updated, field) == value
    assert getattr(record, field) != getattr(updated, field)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "field, value",
    [
        ("name", "test" * 255),
        ("username", "test" * 255),
        ("secret", "secret" * 255),
    ],
)
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_update_wallet_record__error(field: str, value: str, user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    record = _create_record(
        user, name="something", username="different", secret="from", description="parametrize"  # noqa: S106
    )
    with pytest.raises(ValidationError, match=re.compile(r"Ensure this value has at most \d+ characters.")):
        Wallet.objects.update_record(user=user, record_id=record.pk, **{field: value})


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_wallet_record_get_decrypted_record_secret(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    secret_value = "some secret value"  # noqa: S105
    record = _create_record(user, secret=secret_value)
    assert Wallet.objects.get_decrypted_record_secret(user, record) == secret_value
    assert record.secret != secret_value


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_wallet_delete_record__successful(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    assert WalletRecord.objects.count() == 0
    record = _create_record(user)
    assert WalletRecord.objects.count() == 1
    assert Wallet.objects.delete_record(user=user, record_id=record.pk)
    assert WalletRecord.objects.count() == 0


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_wallet_delete_record__non_existing(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    assert WalletRecord.objects.count() == 0
    _create_record(user)
    assert WalletRecord.objects.count() == 1
    with pytest.raises(WalletRecord.DoesNotExist):
        Wallet.objects.delete_record(user=user, record_id="123")


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_wallet_get_records__one_user(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    assert WalletRecord.objects.count() == 0
    record = _create_record(user)
    assert WalletRecord.objects.count() == 1
    records = Wallet.objects.get_records(user)
    assert records.count() == 1
    assert records[0].pk == record.pk


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor"])
def test_wallet_get_records__multiple_users(user_fixture: str, request: FixtureRequest, accountant: User) -> None:
    user = request.getfixturevalue(user_fixture)
    assert WalletRecord.objects.count() == 0
    number_of_records = 10
    for _ in range(number_of_records):
        _create_record(user)
    assert WalletRecord.objects.count() == number_of_records
    records = Wallet.objects.get_records(user)
    assert records.count() == number_of_records
    assert Wallet.objects.get_records(accountant) != records
    assert Wallet.objects.get_records(accountant).count() == 0


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_walet_get_record__successful(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    assert WalletRecord.objects.count() == 0
    record = _create_record(user)
    assert WalletRecord.objects.count() == 1
    assert Wallet.objects.get_record(user, record_id=record.pk) == record


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_walet_get_record__non_existing(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    assert WalletRecord.objects.count() == 0
    _create_record(user)
    assert WalletRecord.objects.count() == 1
    with pytest.raises(WalletRecord.DoesNotExist):
        Wallet.objects.get_record(user, record_id="123")


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_wallet_records__change_pasword(user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    assert WalletRecord.objects.count() == 0
    number_of_records = 10
    for _ in range(number_of_records):
        _create_record(user)
    records = Wallet.objects.get_records(user)
    assert records.count() == number_of_records
    assert WalletRecord.objects.count() == number_of_records
    old_password = user.password
    user.set_password("new-password")
    Wallet.objects.change_password(user, old_password)
    assert user.password != old_password
    assert records != Wallet.objects.get_records(user)
    assert Wallet.objects.get_records(user).count() == number_of_records
