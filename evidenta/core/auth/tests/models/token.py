from datetime import datetime, timedelta

from django.conf import settings
from django.utils import timezone

import pytest
from freezegun import freeze_time

from evidenta.common.testing.utils import assert_count, assert_equal
from evidenta.core.auth.models import Token
from evidenta.core.user.models import User


@freeze_time(timezone.now())
@pytest.mark.django_db
def test_create_token_should_successfully_pass(random_token: str, admin: User) -> None:
    Token.objects.create(
        token=random_token,
        user=admin,
        expires_at=timezone.now() + timedelta(minutes=settings.INVITATION_LINK_TOKEN_EXPIRATION_MINS),
    )
    qs = Token.objects.filter()
    assert_count(qs, 1)
    token = qs.first()
    assert_equal(token.token, random_token)
    assert_equal(token.user, admin)
    assert_equal(token.expires_at, timezone.now() + timedelta(minutes=settings.INVITATION_LINK_TOKEN_EXPIRATION_MINS))
    assert token.is_valid()


@freeze_time(timezone.now())
@pytest.mark.django_db
@pytest.mark.parametrize(
    "expires_at,is_valid",
    [
        (timezone.now() + timedelta(days=10), True),
        (timezone.make_aware(datetime(1970, 1, 1), timezone.get_current_timezone()), False),
    ],
)
def test_token_is_valid(random_token: str, admin: User, expires_at: datetime, is_valid: bool) -> None:
    Token.objects.create(
        token=random_token,
        user=admin,
        expires_at=expires_at,
    )
    qs = Token.objects.filter()
    assert_count(qs, 1)
    token = qs.first()
    assert token.is_valid() is is_valid
