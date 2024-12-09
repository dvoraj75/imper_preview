import secrets
import string
from unittest.mock import MagicMock

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.test import Client

import pytest
import pytest_django
from _pytest.fixtures import SubRequest

from evidenta.common.enums import ApiErrorCode
from evidenta.common.management.data.init_data import create_roles_and_permissions
from evidenta.common.testing.utils import generate_mutation, generate_random_company_data, generate_random_user_data
from evidenta.core.auth.exceptions import InvalidTokenError
from evidenta.core.company.models import Company
from evidenta.core.user.enums import UserRole
from evidenta.core.user.models import Role, User
from evidenta.core.wallet.models import Wallet


@pytest.fixture(scope="session")
def django_db_setup(django_db_setup, django_db_blocker: pytest_django.plugin.DjangoDbBlocker) -> None:
    with django_db_blocker.unblock():
        for fixture in settings.TEST_FIXTURES_FILES:
            call_command("loaddata", fixture)
        create_roles_and_permissions()


@pytest.fixture
def drop_all_roles():
    Role.objects.filter().delete()


@pytest.fixture
def django_client():
    return Client()


@pytest.fixture
def empty_filter_mock():
    magic = MagicMock()
    magic.filter.return_value = magic
    return magic


@pytest.fixture
def base_user_mutation_input() -> dict[str, str]:
    return {
        "firstName": "test",
        "lastName": "test",
        "username": "test",
        "email": "test@email.com",
        "role": UserRole.GUEST,
    }


@pytest.fixture
def create_user_mutation_query(base_user_mutation_input, request):
    if hasattr(request, "param"):
        for e in request.param.get("exclude", []):
            base_user_mutation_input.pop(e, None)
        base_user_mutation_input.update(**request.param.get("extra", {}))
    return generate_mutation("createUser", **base_user_mutation_input)


@pytest.fixture
def update_user_mutation_query(base_user_mutation_input, request):
    base_user_mutation_input["userId"] = "VXNlck5vZGU6Mw=="
    if hasattr(request, "param"):
        for e in request.param.get("exclude", []):
            base_user_mutation_input.pop(e, None)
        base_user_mutation_input.update(**request.param.get("extra", {}))
    return generate_mutation("updateUser", **base_user_mutation_input)


@pytest.fixture
def delete_user_mutation_query():
    return generate_mutation("deleteUser", **{"userId": "VXNlck5vZGU6Mw=="})


@pytest.fixture
def mutation_query(request) -> str:
    return generate_mutation(request.param.get("mutation"), **request.param.get("input"))


@pytest.fixture
def mock_function_create_or_update():
    def _f(*args, **kwargs) -> MagicMock:
        mock = MagicMock()
        for key, value in kwargs.items():
            setattr(mock, key, value)
        return mock

    return _f


@pytest.fixture
def mock_function_invalid_data_error():
    def _f(*args, **kwargs):
        raise ValidationError(message="Some random error", code=ApiErrorCode.INVALID_VALUES)

    return _f


@pytest.fixture
def admin() -> User:
    user_data = generate_random_user_data()
    admin_role = Role.objects.get(role=UserRole.ADMIN)
    user_data.update({"username": "admin", "role": admin_role, "email": "admin@admin.cz"})
    ret = User.objects.create_superuser(**user_data)
    Wallet.objects.create_wallet(ret)
    return ret


@pytest.fixture
def supervisor() -> User:
    user_data = generate_random_user_data()
    user_data.update({"username": "supervisor", "role": UserRole.SUPERVISOR})
    ret = User.objects.create(**user_data)
    Wallet.objects.create_wallet(ret)
    return ret


@pytest.fixture
def accountant() -> User:
    user_data = generate_random_user_data()
    user_data.update({"username": "accountant", "role": UserRole.ACCOUNTANT})
    ret = User.objects.create(**user_data)
    Wallet.objects.create_wallet(ret)
    return ret


@pytest.fixture
def client() -> User:
    user_data = generate_random_user_data()
    user_data.update({"username": "client", "role": UserRole.CLIENT})
    ret = User.objects.create(**user_data)
    Wallet.objects.create_wallet(ret)
    return ret


@pytest.fixture
def guest() -> User:
    user_data = generate_random_user_data()
    user_data.update({"username": "guest", "role": UserRole.GUEST})
    ret = User.objects.create(**user_data)
    Wallet.objects.create_wallet(ret)
    return ret


@pytest.fixture
def user_data(request: SubRequest) -> dict[str, any]:
    user_data = generate_random_user_data()
    if hasattr(request, "param"):
        user_data.update(request.param)
    return user_data


@pytest.fixture
def super_user_data(request: SubRequest, user_data: dict[str, any]) -> dict[str, any]:
    user_data.update(
        {
            "username": "JohnDoeAdmin",
            "role": UserRole.ADMIN,
        }
    )
    if hasattr(request, "param"):
        user_data.update(request.param)
    return user_data


@pytest.fixture
def user_data_with_companies(
    request: SubRequest, user_data: dict[str, any], random_companies: list[Company]
) -> dict[str, any]:
    user_data.update({"companies": random_companies})
    if hasattr(request, "param"):
        user_data.update(request.param)
    return user_data


def _create_user(**user_data: dict[str, any]) -> User:
    user = User.objects.create(**user_data)
    Wallet.objects.create_wallet(user)
    return user


@pytest.fixture
def random_user(user_data: dict[str, any]) -> User:
    return _create_user(**user_data)


@pytest.fixture
def random_users(request: SubRequest) -> list[User]:
    return [
        _create_user(**generate_random_user_data()) for _ in range(request.param if hasattr(request, "param") else 2)
    ]


@pytest.fixture
def company_data(request: SubRequest) -> dict[str, any]:
    return generate_random_company_data()


def _create_company(**company_data: dict[str, any]) -> Company:
    return Company.objects.create(**company_data)


@pytest.fixture
def random_company(company_data) -> Company:
    return _create_company(**company_data)


@pytest.fixture
def random_companies(request: SubRequest) -> list[Company]:
    return [
        _create_company(**generate_random_company_data())
        for _ in range(request.param if hasattr(request, "param") else 2)
    ]


@pytest.fixture
def random_token():
    return secrets.token_urlsafe(settings.DEFAULT_TOKEN_LENGTH)


@pytest.fixture
def random_otp_token():
    return "".join(secrets.choice(string.digits) for _ in range(settings.DEFAULT_OTP_TOKEN_LENGTH))


@pytest.fixture
def valid_token_mock(random_token):
    mock_token = MagicMock()
    mock_token.is_valid.return_value = True
    mock_token.user.pk = 1
    mock_token.token = random_token
    return mock_token


@pytest.fixture
def invalid_token_mock():
    mock_token = MagicMock()
    mock_token.is_valid.return_value = False
    mock_token.user.pk = 1000
    return mock_token


@pytest.fixture
def user_mock():
    mock_user = MagicMock()
    mock_user.pk = 1
    return mock_user


@pytest.fixture
def invalid_token_error() -> InvalidTokenError:
    return InvalidTokenError(
        "Invalid token.",
        code=ApiErrorCode.INVALID_TOKEN,
    )


@pytest.fixture
def validation_error() -> ValidationError:
    return ValidationError(
        "Some random error",
        code=ApiErrorCode.INVALID_TOKEN,
    )
