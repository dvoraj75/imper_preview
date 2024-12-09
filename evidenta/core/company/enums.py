from enum import auto

from django.db import models
from django.utils.translation import gettext_lazy as _


#
class CompanyFormOfBusiness(models.IntegerChoices):
    FREELANCER = auto(), _("Freelancer")
    LEGAL_ENTITY = auto(), _("Legal entity")


class NaturalPersonType(models.IntegerChoices):
    NOTIFIABLE_TRADE = auto(), _("Notifiable trade")
    LICENSED_TRADE = auto(), _("Licensed trade")


class LegalPersonType(models.IntegerChoices):
    LIMITED_COMPANY = auto(), _("Limited company")
    LIMITED_STOCK_COMPANY = auto(), _("Limited stock company")
    PUBLIC_STOCK_COMPANY = auto(), _("Public stock company")
    GENERAL_PARTNERSHIP = auto(), _("General partnership")
    LIMITED_PARTNERSHIP = auto(), _("Limited partnership")
    COOPERATIVE = auto(), _("Cooperative")
    HOUSING_COOPERATIVE = auto(), _("Housing cooperative")
    SOCIETAS_EUROPAEA = auto(), _("Societas europaea")
