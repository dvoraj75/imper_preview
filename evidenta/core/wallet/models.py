from datetime import timedelta
from typing import Any

from django.db import models
from django.db.models import QuerySet
from django.utils.datetime_safe import datetime

from app_settings import settings
from evidenta.common.models.base import BaseModel
from evidenta.core.user.models import User
from evidenta.core.wallet.crypto_manager import CryptoManager


class WalletManager(models.Manager):
    def __init__(self):
        super().__init__()
        self._crypto_manager = CryptoManager()

    def create_wallet(self, user: User) -> "Wallet":
        salt = self._crypto_manager.generate_salt()
        return super().create(user=user, salt=salt)

    def _create_encrypted_record(self, user: User, **record_data) -> tuple[dict[str, Any], str]:
        secret = record_data["secret"]
        encrypted_secret, nonce = self._crypto_manager.encrypt_data(secret, user.password, user.wallet.salt)
        record_data["secret"] = encrypted_secret

        return record_data, nonce

    def create_record(self, user: User, **record_data) -> "WalletRecord":
        encrypted_data, nonce = self._create_encrypted_record(user, **record_data)
        return WalletRecord.objects.create(wallet=user.wallet, nonce=nonce, **encrypted_data)

    def update_record(self, user: User, record_id: str, **record_data) -> "WalletRecord":
        record = WalletRecord.objects.get(wallet=user.wallet, pk=record_id)
        if "secret" in record_data:
            encrypted_data, nonce = self._create_encrypted_record(user, **record_data)
            record.update(**encrypted_data, nonce=nonce)
        else:
            record.update(**record_data)
        record.save()
        return record

    def get_decrypted_record_secret(self, user: User, record: "WalletRecord") -> str:
        return self._crypto_manager.decrypt_data(record.secret, user.password, user.wallet.salt, record.nonce)

    def delete_record(self, user: User, record_id: str) -> "WalletRecord":
        record = user.wallet.walletrecord_set.get(pk=record_id)
        record.delete()
        return record

    def get_records(self, user: User) -> QuerySet["WalletRecord"]:
        return user.wallet.walletrecord_set.all()

    def get_record(self, user: User, record_id: str) -> "WalletRecord":
        return user.wallet.walletrecord_set.get(pk=record_id)

    def change_password(self, user: User, old_password: str) -> None:
        for record in WalletRecord.objects.filter(wallet=user.wallet):
            decrypted_secret = self._crypto_manager.decrypt_data(
                record.secret, old_password, user.wallet.salt, record.nonce
            )
            encrypted_secret, nonce = self._crypto_manager.encrypt_data(
                decrypted_secret, user.password, user.wallet.salt
            )
            record.update(secret=encrypted_secret, nonce=nonce)
            record.save()


class WalletRecord(BaseModel):
    """Record contains encrypted data from wallet."""

    wallet = models.ForeignKey("Wallet", on_delete=models.CASCADE)

    name = models.CharField(max_length=255, blank=False)
    username = models.CharField(max_length=255, blank=False)
    secret = models.CharField(max_length=255, blank=False)
    description = models.TextField(blank=True, default="")

    nonce = models.CharField(max_length=64, blank=False)


class Wallet(BaseModel):
    """User wallet storing secrets."""

    objects = WalletManager()

    user = models.OneToOneField(User, on_delete=models.CASCADE, blank=True, null=True)
    salt = models.CharField(max_length=32, blank=False)

    last_activity_at = models.DateTimeField(blank=True, null=True, default=None)

    def is_unlocked(self) -> bool:
        return self.last_activity_at is not None and datetime.now() < self.last_activity_at + timedelta(
            minutes=settings.WALLET_UNLOCK_EXPIRATION_TIME_MINS
        )

    def update_activity(self):
        self.last_activity_at = datetime.now()
