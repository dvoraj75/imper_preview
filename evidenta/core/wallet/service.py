from django.contrib.auth.hashers import check_password
from django.core.exceptions import PermissionDenied
from django.db.models import QuerySet

from evidenta.common.services.base import BaseService
from evidenta.core.user.models import User
from evidenta.core.wallet.models import Wallet, WalletRecord


class WalletService(BaseService):

    manager = Wallet.objects

    def create_wallet(self, user: User) -> Wallet:
        return self.manager.create_wallet(user)

    def create_record(self, user: User, **record_data) -> WalletRecord:
        return self.manager.create_record(user, **record_data)

    def update_record(self, user: User, record_id: str, **record_data) -> WalletRecord:
        return self.manager.update_record(user, record_id, **record_data)

    def change_password(self, user: User, old_password: str) -> None:
        return self.manager.change_password(user, old_password)

    def delete_record(self, user: User, record_id: str) -> WalletRecord:
        return self.manager.delete_record(user, record_id)

    def get_records(self, user: User) -> QuerySet[WalletRecord]:
        return self.manager.get_records(user)

    def get_record(self, user: User, record_id: str) -> WalletRecord:
        return self.manager.get_record(user, record_id)

    def unlock_wallet(self, user: User, user_password: str):
        if check_password(user_password, user.password):
            # TODO: Set timestamp in user db? Create cookie with timestamp?
            ...
        else:
            raise PermissionDenied
