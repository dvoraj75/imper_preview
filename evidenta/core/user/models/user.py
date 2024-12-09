from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import AbstractUser, Permission, UserManager
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models
from django.utils.translation import gettext_lazy as _

from evidenta.common.enums import ApiErrorCode
from evidenta.common.models.base import BaseModel
from evidenta.core.user.enums import UserGender, UserRole
from evidenta.core.user.models import Role


class CustomUserManager(UserManager):
    def create(self, **user_data) -> "User":
        if "password" in user_data:
            user_data["password"] = self.make_and_validate_password(user_data.get("password"))
        user_data["role"] = self.get_role_object(user_data.get("role"))
        companies: list[int] = user_data.pop("companies", [])
        user = super().create(**user_data)
        if companies:
            self.check_if_companies_exists(companies)
            user.set_companies(companies)
        return user

    def get_all_related_users(self, as_user: "User") -> models.QuerySet["User"]:
        match as_user.role.role:
            case UserRole.GUEST:
                return self.filter(id=as_user.id)
            case UserRole.CLIENT | UserRole.ACCOUNTANT:
                return self.filter(companies__in=as_user.companies.filter(), is_superuser=False).distinct()
            case UserRole.SUPERVISOR | UserRole.ADMIN:
                return self.filter()

    def update(self, user_id: int, as_user: "User", **user_data) -> None:
        if "role" in user_data:
            user_data["role"] = self.get_role_object(user_data.get("role"))

        if "companies" in user_data:
            self.check_if_companies_exists(user_data.get("companies"))

        user = self.get_all_related_users(as_user=as_user).get(pk=user_id)
        user.update(**user_data)
        user.save()

    def delete(self, user_id: int, as_user: "User"):
        if not self.get_all_related_users(as_user=as_user).filter(id=user_id).delete()[0]:
            raise User.DoesNotExist(f"Does not exist: user id={user_id} does not exist.")

    @staticmethod
    def get_role_object(role: str) -> Role:
        try:
            return Role.objects.get(role=role)
        except (Role.DoesNotExist, ValueError) as e:
            raise ValidationError(
                f"Role '{role}' does not exist.",
                params={"field": "role", "value": role},
                code=ApiErrorCode.INVALID_CHOICE,
            ) from e

    @staticmethod
    def check_if_companies_exists(companies: list[int]) -> None:
        from evidenta.core.company.models import Company

        if len(companies) != Company.objects.filter(id__in=companies).count():
            raise ValidationError(
                "Some of the company id does not exist.",
                params={"field": "companies", "value": companies},
                code=ApiErrorCode.COMPANY_DOES_NOT_EXIST,
            )

    @staticmethod
    def make_and_validate_password(password: str) -> str:
        validate_password(password)
        return make_password(password)


class User(AbstractUser, BaseModel):
    objects = CustomUserManager()

    username = models.CharField(
        max_length=150,
        unique=True,
        blank=False,
        validators=[AbstractUser.username_validator],
    )
    title = models.CharField(
        max_length=10,
        blank=True,
        default="",
    )
    first_name = models.CharField(
        max_length=150,
        blank=False,
    )
    last_name = models.CharField(
        max_length=150,
        blank=False,
    )
    email = models.EmailField(
        blank=False,
        unique=True,
    )
    role = models.ForeignKey(
        "Role",
        on_delete=models.PROTECT,
        blank=False,
        null=True,
    )
    phone_number = models.CharField(
        max_length=16,
        blank=True,
        default="",
        validators=[
            RegexValidator(
                regex=r"^\+?1?\d{9,15}$",
                message=_("Invalid phone number format."),
            )
        ],
    )
    gender = models.PositiveSmallIntegerField(
        choices=UserGender.choices,
        blank=True,
        null=True,
    )
    birthday = models.DateField(
        auto_now=False,
        null=True,
        blank=True,
    )

    class Meta:
        ordering = ["pk"]
        permissions = [
            ("assign_company_user", "Can assign company to user"),
            ("assign_role", "Can assign role to user"),
            ("assign_supervisor", "Can assign supervisor"),
        ]
        db_table = "user"

    def clean(self):
        super().clean()
        self._clean_string_data()
        if not self.gender:
            self.gender = None

    def _clean_string_data(self):
        if isinstance(self.first_name, str):
            self.first_name = self.first_name.capitalize()

        if isinstance(self.last_name, str):
            self.last_name = self.last_name.capitalize()

        if isinstance(self.email, str):
            self.email = self.email.lower()

    def set_companies(self, companies: list[int]) -> None:
        self.companies.set(companies)

    def has_perm(self, perm: str, obj=None) -> bool:
        return super().has_perm(perm, obj) or (self.role and self.role.permissions.filter(codename=perm).exists())

    def add_permission(self, permission: str | Permission) -> None:
        if not isinstance(permission, Permission):
            permission = Permission.objects.get(codename=permission)
        self.user_permissions.add(permission)

    def can_have_wallet(self) -> bool:
        return self.role.role not in (UserRole.CLIENT, UserRole.GUEST)
