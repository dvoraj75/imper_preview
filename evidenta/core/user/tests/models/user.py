from typing import Any

from django.core.exceptions import ValidationError

import pytest

from evidenta.common.testing.utils import (
    assert_count,
    assert_exists,
    assert_obj_equal,
    assert_obj_not_equal,
    assert_obj_with_dict,
    assert_pk,
    generate_random_user_data,
)
from evidenta.core.company.models import Company
from evidenta.core.user.enums import UserRole
from evidenta.core.user.models import User


@pytest.mark.django_db
@pytest.mark.parametrize(
    "user_data",
    [
        {"username": "test_guest", "email": "guest@test.cz", "role": UserRole.GUEST, "gender": ""},
        {"username": "test_client", "email": "client@test.cz", "role": UserRole.CLIENT, "gender": ""},
        {"username": "test_accountant", "email": "accountant@test.cz", "role": UserRole.ACCOUNTANT, "gender": ""},
        {"username": "test_supervisor", "email": "supervisor@test.cz", "role": UserRole.SUPERVISOR, "gender": ""},
    ],
    indirect=True,
)
def test_create_user_with_all_roles_should_successfully_pass(user_data: dict[str, Any]) -> None:
    user = User.objects.create(**user_data)
    assert_obj_with_dict(user, user_data, extra={"gender": None}, exclude=("password",))
    assert_exists(User, username=user_data["username"])


@pytest.mark.django_db
@pytest.mark.parametrize(
    "user_data",
    [
        {"username": ""},
        {"username": "toolong" * 50},
        {"username": None},
        {"title": "toolong" * 10},
        {"first_name": ""},
        {"first_name": "toolong" * 50},
        {"first_name": None},
        {"last_name": ""},
        {"last_name": "toolong" * 50},
        {"last_name": None},
        {"email": ""},
        {"email": None},
        {"email": "wrong"},
        {"email": "wrong@"},
        {"email": "wrong@email"},
        {"email": "@email.cz"},
        {"email": "email.cz"},
        {"role": ""},
        {"role": None},
        {"role": "Kolotocar"},
        {"phone_number": "123" * 10},
        {"phone_number": "12345678*"},
        {"phone_number": "12345678"},
        {"phone_number": "12345aaa"},
        {"gender": 10},
        {"gender": "Abc"},
        {"birthday": "2023 01.01."},
        {"birthday": "ahoj"},
    ],
    indirect=True,
)
def test_create_user_should_fail_with_validation_error_for_invalid_data(user_data: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        User.objects.create(**user_data)


@pytest.mark.django_db
def test_create_user_with_companies_should_successfully_pass(
    user_data: dict[str, Any], random_company: Company
) -> None:
    user_data["companies"] = [random_company.pk]
    user = User.objects.create(**user_data)
    assert_obj_with_dict(user, user_data, exclude=("password", "companies"))
    assert_count(user.companies, 1)


@pytest.mark.django_db
@pytest.mark.parametrize("user_data", [{"companies": [1, 2, 3]}], indirect=True)
def test_create_user_with_non_exsting_companies_should_fail_with_validation_error(user_data: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        User.objects.create(**user_data)


@pytest.mark.django_db
@pytest.mark.parametrize("as_user", ["guest"])
def test_get_all_for_guest_role_should_return_guest_user_only(request, as_user: str) -> None:
    user = request.getfixturevalue(as_user)
    result = User.objects.get_all_related_users(as_user=user)
    assert_count(result, 1)
    assert_pk(user, result.first())


@pytest.mark.django_db
@pytest.mark.parametrize("as_user", ["client", "accountant"])
def test_get_all_for_client_and_accountant_should_return_related_users_only(
    request, as_user: str, random_company: Company, random_users: list[User]
) -> None:
    as_user: User = request.getfixturevalue(as_user)
    as_user.set_companies([random_company.pk])
    random_users[0].set_companies([random_company.pk])
    assert_count(User.objects.get_all_related_users(as_user=as_user), 2)


@pytest.mark.django_db
@pytest.mark.parametrize("as_user", ["supervisor", "admin"])
@pytest.mark.usefixtures("random_users")
def test_get_all_for_management_roles_should_return_all_users(request, as_user: str) -> None:
    user = request.getfixturevalue(as_user)
    assert_count(User.objects.get_all_related_users(as_user=user), 3)


@pytest.mark.django_db
@pytest.mark.parametrize("user_to_update", ["guest", "client", "accountant", "supervisor", "admin"])
@pytest.mark.parametrize("as_user", ["admin"])
def test_update_user_with_all_roles_successfully(
    request, user_to_update: str, as_user: str, random_companies: list[Company]
) -> None:
    user_to_update = request.getfixturevalue(user_to_update)
    as_user = request.getfixturevalue(as_user)
    user_data = generate_random_user_data()
    user_data["companies"] = [company.pk for company in random_companies]
    User.objects.update(user_id=user_to_update.pk, as_user=as_user, **user_data)
    updated_user = User.objects.get(pk=user_to_update.pk)
    assert_obj_not_equal(user_to_update, updated_user)
    assert_obj_with_dict(updated_user, user_data, exclude=("password", "companies"))
    assert_count(updated_user.companies, len(random_companies))


@pytest.mark.django_db
def test_update_user_with_non_existing_companies_should_fail_with_validation_error(admin: User) -> None:
    with pytest.raises(ValidationError):
        User.objects.update(1, as_user=admin, companies=[1, 2, 3])


@pytest.mark.django_db
@pytest.mark.parametrize("user_to_update", ["guest", "client", "accountant", "supervisor", "admin"])
@pytest.mark.parametrize("as_user", ["admin"])
def test_update_user_with_empty_kwargs_successfully_finnish_with_no_changes(
    request, user_to_update: str, as_user: str
) -> None:
    user_to_update = request.getfixturevalue(user_to_update)
    as_user = request.getfixturevalue(as_user)
    User.objects.update(user_id=user_to_update.pk, as_user=as_user)
    updated_user = User.objects.get(pk=user_to_update.pk)
    assert_obj_equal(user_to_update, updated_user)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "invalid_data",
    [
        {"username": ""},
        {"username": "toolong" * 50},
        {"username": None},
        {"title": "toolong" * 10},
        {"first_name": ""},
        {"first_name": "toolong" * 50},
        {"first_name": None},
        {"last_name": ""},
        {"last_name": "toolong" * 50},
        {"last_name": None},
        {"email": ""},
        {"email": None},
        {"email": "wrong"},
        {"email": "wrong@"},
        {"email": "wrong@email"},
        {"email": "@email.cz"},
        {"email": "email.cz"},
        {"role": ""},
        {"role": None},
        {"role": "Kolotocar"},
        {"phone_number": "123" * 10},
        {"phone_number": "12345678*"},
        {"phone_number": "12345678"},
        {"phone_number": "12345aaa"},
        {"gender": 10},
        {"gender": "Abc"},
        {"birthday": "2023 01.01."},
        {"birthday": "ahoj"},
    ],
)
def test_update_user_with_invalid_data_should_fail_with_validation_error(
    admin: User, random_user: User, invalid_data: dict[str, any]
) -> None:
    with pytest.raises(ValidationError):
        User.objects.update(user_id=random_user.pk, as_user=admin, **invalid_data)


@pytest.mark.django_db
def test_update_non_existing_user_should_fail_with_does_not_exist_error(admin):
    with pytest.raises(User.DoesNotExist):
        User.objects.update(user_id=123, as_user=admin)


@pytest.mark.django_db
def test_delete_user_successfully(admin, random_user: User) -> None:
    assert_count(User.objects.filter(), 2)
    User.objects.delete(user_id=random_user.pk, as_user=admin)
    assert_count(User.objects.filter(), 1)
    with pytest.raises(User.DoesNotExist):
        User.objects.get(pk=random_user.pk)


@pytest.mark.django_db
def test_delete_non_existing_user_should_fail_with_does_not_exist_error(admin):
    with pytest.raises(User.DoesNotExist):
        User.objects.delete(user_id=123, as_user=admin)


@pytest.mark.django_db
@pytest.mark.parametrize(
    "perm",
    [
        "can_kill_trump",
        "can_date_gal_gadot",
        "can_play_in_star_wars",
    ],
)
def test_has_perm_should_return_always_true_for_admin(admin: User, perm: str) -> None:
    assert admin.has_perm(perm)
