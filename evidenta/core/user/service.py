from typing import cast

from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.db import models, transaction

from evidenta.common.services.base import BaseService
from evidenta.common.utils import create_url
from evidenta.core.auth.service import AuthService
from evidenta.core.notifications.service import NotificationService
from evidenta.core.wallet.service import WalletService

from .enums import ResourcePath
from .models import User


class UserService(BaseService):
    manager = User.objects

    def __init__(self):
        super().__init__()
        self.wallet_service = WalletService()

    def create(self, **user_data) -> User:
        with transaction.atomic():
            user = self.manager.create(**user_data)
            self.wallet_service.create_wallet(user)
            self.invite_user(user)
        return user

    def get_from_related(self, as_user: User, **kwargs) -> User:
        return self.get_all_related(as_user=as_user).get(**kwargs)

    def get_all_related(self, *args, **kwargs) -> models.QuerySet[User]:
        return self.manager.get_all_related_users(*args, **kwargs)

    def update(self, user_id: str, as_user: User, **user_data) -> None:
        with transaction.atomic():
            updated_user = self.manager.get(pk=user_id)
            old_password = updated_user.password
            self.manager.update(user_id=user_id, as_user=as_user, **user_data)
            if "password" in user_data:
                self.wallet_service.change_password(updated_user, old_password)
            # todo: mozna nejake dalsi notifikace

    def delete(self, user_id: str, **kwargs) -> None:
        self.manager.delete(user_id=user_id, **kwargs)

    def set_user_password(self, user: User, password: str) -> None:
        with transaction.atomic():
            validate_password(password)
            old_password = user.password
            user.set_password(password)
            user.save()
            self.wallet_service.change_password(user, old_password)

    def invite_user_by_email(self, as_user: User, email: str) -> None:
        self.invite_user(user=self.get_from_related(as_user=as_user, email=email))

    @staticmethod
    def invite_user(user: User) -> None:
        token = AuthService().create_token_for_user(
            user,
            settings.INVITATION_LINK_TOKEN_EXPIRATION_MINS,
        )
        NotificationService().send_invitation_link(
            user=user, link=create_url(settings.FRONTEND_URL, ResourcePath.SETUP_PASSWORD, token=token)
        )

    def set_password_to_user_by_token(self, token: str, password: str) -> None:
        with transaction.atomic():
            auth_service = AuthService()
            token = auth_service.get_token(token)
            auth_service.validate_token(token)
            self.set_user_password(token.user, password)
            auth_service.delete_token(token)

    def request_password_change(self, email: str, as_user: User) -> None:
        with transaction.atomic():
            user = self.get_from_related(as_user=as_user, email=email)
            otp_token = AuthService().create_otp_token_for_user(
                user=user, validity_time=settings.CHANGE_PASSWORD_OTP_TOKEN_EXPIRATION_MINS
            )
            NotificationService().send_update_password_otp(user=user, otp=str(otp_token))

    def change_user_password_by_token(self, token: str, password: str, as_user: User) -> None:
        with transaction.atomic():
            auth_service = AuthService()
            otp_token = auth_service.get_otp_token(token)
            auth_service.validate_otp_token(otp_token, as_user)
            self.set_user_password(otp_token.user, password)
            auth_service.delete_token(otp_token)

    def request_password_reset(self, email: str) -> None:
        with transaction.atomic():
            user = cast(User, self.get(email=email))
            token = AuthService().create_token_for_user(user, settings.RESET_PASSWORD_LINK_TOKEN_EXPIRATION_MINS)
            NotificationService().send_reset_password_link(
                user=user, link=create_url(settings.FRONTEND_URL, ResourcePath.RESET_PASSWORD, token=token)
            )
