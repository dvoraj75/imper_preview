import secrets
import string
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from evidenta.common.enums import ApiErrorCode
from evidenta.core.auth.exceptions import InvalidTokenError
from evidenta.core.auth.models import OTPToken, Token
from evidenta.core.user.models import User


class AuthService:
    @staticmethod
    def validate_token(token: Token | OTPToken) -> None:
        if not token.is_valid():
            raise InvalidTokenError(
                "Invalid token.",
                code=ApiErrorCode.INVALID_TOKEN,
            )

    def validate_otp_token(self, token: OTPToken, user: User) -> None:
        if user.pk != token.user.pk:
            raise InvalidTokenError(
                "Invalid token.",
                code=ApiErrorCode.INVALID_TOKEN,
            )
        self.validate_token(token)

    @staticmethod
    def create_token_for_user(
        user: User, validity_time: int, token_length: int = settings.DEFAULT_TOKEN_LENGTH
    ) -> Token:
        return Token.objects.create(
            user=user,
            token=secrets.token_urlsafe(token_length),
            expires_at=timezone.now() + timedelta(minutes=validity_time),
        )

    def create_otp_token_for_user(
        self, user: User, validity_time: int, token_length: int = settings.DEFAULT_OTP_TOKEN_LENGTH
    ) -> OTPToken:
        return OTPToken.objects.create(
            user=user,
            token=self._generate_otp_token(token_length),
            expires_at=timezone.now() + timedelta(minutes=validity_time),
        )

    @staticmethod
    def _generate_otp_token(token_length: int = None) -> str:
        return "".join(secrets.choice(string.digits) for _ in range(token_length or settings.DEFAULT_OTP_TOKEN_LENGTH))

    @staticmethod
    def get_token(token: str) -> Token:
        return Token.objects.get(token=token)

    @staticmethod
    def get_otp_token(token: str) -> OTPToken:
        return OTPToken.objects.get(token=token)

    @staticmethod
    def delete_token(token: Token | OTPToken) -> None:
        token.delete()
