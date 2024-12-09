from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator
from django.db import models
from django.db.utils import IntegrityError

from evidenta.common.exceptions import IntegrityException, NonUniqueErrorException
from evidenta.common.models.base import BaseModel
from evidenta.core.user.enums import UserRole
from evidenta.core.user.models.user import User

from .validators import CompanyIdentificationNumberValidator


class CompanyManager(models.Manager):
    def create(self, **company_data: dict[str, any]) -> "Company":
        users: list[int] = company_data.pop("users", [])
        try:
            company: Company = super().create(**company_data)
            company.set_users(users)
        except ValidationError as e:
            raise NonUniqueErrorException(str(e), params=e.error_dict if hasattr(e, "error_dict") else {}) from e
        except IntegrityError as e:
            raise IntegrityException(str(e), params={"users": company_data.get("companies")}) from e
        return company

    def get_all_related_companies(self, as_user: User) -> models.QuerySet["Company"]:
        match as_user.role:
            case UserRole.ADMIN | UserRole.SUPERVISOR:
                return self.all()
            case _:
                return as_user.companies.all()

    def update(self, company_id: int, as_user: User, **company_data) -> None:
        self.clean_and_validate_data(company_data)
        try:
            company = self.get_all_related_companies(as_user=as_user).get(pk=company_id)
            company.update(**company_data)
            company.save()
        except ValidationError as e:
            raise NonUniqueErrorException(str(e), params=e.error_dict if hasattr(e, "error_dict") else {}) from e
        except IntegrityError as e:
            raise IntegrityException(str(e), {"users:": company_data.get("users")}) from e

    def delete(self, company_id, as_user: "User") -> None:
        if not self.get_all(as_user=as_user).filter(id=company_id).delete()[0]:
            raise Company.DoesNotExist(f"Does not exist: company id={company_id} does not exist.")


class Company(BaseModel):
    objects = CompanyManager()

    name = models.CharField(max_length=50, default="")
    description = models.CharField(max_length=200, blank=True, default="")
    company_identification_number = models.CharField(
        max_length=8,
        validators=[MinLengthValidator(8), CompanyIdentificationNumberValidator()],
        unique=True,
        default=None,
    )
    tax_identification_number = models.CharField(max_length=16, blank=True, default="", unique=True)

    # todo: adresu porasit malicko jinak - vlastni model nebo specialni field
    address_1 = models.CharField(max_length=128)
    address_2 = models.CharField(max_length=128, blank=True, default="")
    city = models.CharField(max_length=64)
    zip_code = models.CharField(max_length=5, validators=[MinLengthValidator(5)])

    users = models.ManyToManyField("user.User", related_name="companies", blank=True)

    class Meta:
        verbose_name_plural = "Companies"
        db_table = "company"

    def set_users(self, users: list[int]) -> None:
        self.users.set(users)

    def __str__(self) -> str:
        return self.name
