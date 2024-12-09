from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import Client

import pytest
from graphene_django.utils.testing import graphql_query
from graphql_relay import to_global_id
from pytest import FixtureRequest

from evidenta.common.enums import ApiErrorCode
from evidenta.common.testing.utils import assert_equal, extract_error_code_from_graphql_error_response
from evidenta.core.user.models import User
from evidenta.core.wallet.models import Wallet, WalletRecord
from evidenta.core.wallet.service import WalletService


DELETE_RECORD_MUTATION = """
mutation deleteWalletRecord($deleteWalletRecordInput:WalletRecordsDeleteInput!) {
  deleteRecord(input:$deleteWalletRecordInput) {
    walletRecord {
      name
    }
  }
}
"""


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_delete_wallet_record_mutation__success(django_client: Client, user_fixture: str, request: FixtureRequest):
    user: User = request.getfixturevalue(user_fixture)
    django_client.force_login(user)
    record_data = {"name": "testing", "username": "test", "secret": "secret", "description": "blabla"}
    record = Wallet.objects.create_record(user, **record_data)
    variables = {"deleteWalletRecordInput": dict(recordId=to_global_id("WalletRecord", record.pk))}
    with patch.object(WalletService, "delete_record", return_value=record) as mock_delete_record:
        response = graphql_query(
            DELETE_RECORD_MUTATION, operation_name="deleteWalletRecord", variables=variables, client=django_client
        )
        mock_delete_record.assert_called_once_with(user, str(record.pk))
        assert response.status_code == 200
        assert response.json().get("data")


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["client", "guest"])
def test_delete_wallet_record_mutation__permission_denied(
    django_client: Client, user_fixture: str, request: FixtureRequest
):
    user: User = request.getfixturevalue(user_fixture)
    django_client.force_login(user)
    variables = {"deleteWalletRecordInput": dict(recordId=to_global_id("WalletRecord", "1"))}
    response = graphql_query(
        DELETE_RECORD_MUTATION, operation_name="deleteWalletRecord", variables=variables, client=django_client
    )
    assert_equal(response.status_code, 400)
    assert_equal(
        extract_error_code_from_graphql_error_response(response.json()), ApiErrorCode.PERMISSION_REQUIRED.value
    )


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
@pytest.mark.parametrize(
    "effect",
    [
        ValidationError("wrong data"),
        ValueError("too long salt"),
        AttributeError("something went wrong"),
        WalletRecord.DoesNotExist,
    ],
)
def test_delete_wallet_record_mutation__fail(
    django_client: Client, user_fixture: str, effect: Exception, request: FixtureRequest
) -> None:
    user: User = request.getfixturevalue(user_fixture)
    django_client.force_login(user)
    variables = {"deleteWalletRecordInput": {"recordId": to_global_id("WalletRecord", "123")}}
    with patch.object(WalletService, "delete_record", side_effect=effect) as mock_delete_record:
        response = graphql_query(
            DELETE_RECORD_MUTATION, operation_name="deleteWalletRecord", variables=variables, client=django_client
        )
        assert_equal(response.status_code, 400)
        assert response.json().get("errors")
        mock_delete_record.assert_called_once_with(user, "123")


def test_create_wallet_record__user_logged_out(django_client: Client):
    variables = {"deleteWalletRecordInput": dict(recordId=to_global_id("WalletRecord", "123"))}
    response = graphql_query(
        DELETE_RECORD_MUTATION, operation_name="deleteWalletRecord", variables=variables, client=django_client
    )
    assert_equal(response.status_code, 400)
    assert_equal(extract_error_code_from_graphql_error_response(response.json()), ApiErrorCode.LOGIN_REQUIRED.value)
