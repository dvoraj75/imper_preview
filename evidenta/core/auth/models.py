from django.db import models

from evidenta.common.models.base import BaseTokenModel


class Token(BaseTokenModel):
    token = models.CharField(max_length=88, unique=True)


class OTPToken(BaseTokenModel):
    token = models.CharField(max_length=6)
