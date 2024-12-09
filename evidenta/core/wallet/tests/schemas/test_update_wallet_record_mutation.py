from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import Client

import pytest
from graphene_django.utils.testing import graphql_query
from graphql_relay import to_global_id
from pytest import FixtureRequest

from evidenta.common.enums import ApiErrorCode
from evidenta.common.testing.utils import assert_equal, extract_error_code_from_graphql_error_response
from evidenta.core.wallet.models import Wallet, WalletRecord
from evidenta.core.wallet.service import WalletService


UPDATE_RECORD_MUTATION = """
mutation updateWalletRecord($updateWalletRecordInput:WalletRecordsUpdateInput!) {
  updateRecord(input:$updateWalletRecordInput) {
    walletRecord{
      name
      username
      description
      id
    }
  }
}
"""


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_update_wallet_record__success(django_client: Client, user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    django_client.force_login(user)
    record_data = {"name": "testing", "username": "test", "secret": "secret", "description": "blabla"}
    record = Wallet.objects.create_record(user, **record_data)
    variables = {"updateWalletRecordInput": dict(**record_data, recordId=to_global_id("WalletRecord", record.pk))}
    with patch.object(WalletService, "update_record", return_value=record) as mock_update_record:
        response = graphql_query(
            UPDATE_RECORD_MUTATION, operation_name="updateWalletRecord", variables=variables, client=django_client
        )
        mock_update_record.assert_called_once_with(user, str(record.pk), **record_data)
        assert response.status_code == 200
        assert response.json().get("data")


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["client", "guest"])
def test_update_wallet_record__permission_denied(
    django_client: Client, user_fixture: str, request: FixtureRequest
) -> None:
    user = request.getfixturevalue(user_fixture)
    django_client.force_login(user)
    record_data = {"name": "testing", "username": "test", "secret": "secret", "description": "blabla"}
    variables = {"updateWalletRecordInput": dict(**record_data, recordId=to_global_id("WalletRecord", "123"))}
    response = graphql_query(
        UPDATE_RECORD_MUTATION, operation_name="updateWalletRecord", variables=variables, client=django_client
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
def test_update_wallet_record__fail(
    django_client: Client, user_fixture: str, effect: Exception, request: FixtureRequest
) -> None:
    user = request.getfixturevalue(user_fixture)
    django_client.force_login(user)
    record_data = {"name": "testing", "username": "test", "secret": "secret", "description": "blabla"}
    variables = {"updateWalletRecordInput": dict(**record_data, recordId=to_global_id("WalletRecord", "123"))}
    with patch.object(WalletService, "update_record", side_effect=effect) as mock_update_record:
        response = graphql_query(
            UPDATE_RECORD_MUTATION, operation_name="updateWalletRecord", variables=variables, client=django_client
        )
        mock_update_record.assert_called_once_with(user, "123", **record_data)
        assert response.status_code == 400
        assert response.json().get("errors")


def test_update_wallet_record__user_not_logged_in(django_client: Client):
    record_data = {"name": "testing", "username": "test", "secret": "secret", "description": "blabla"}
    variables = {"updateWalletRecordInput": dict(**record_data, recordId=to_global_id("WalletRecord", "123"))}
    response = graphql_query(
        UPDATE_RECORD_MUTATION, operation_name="updateWalletRecord", variables=variables, client=django_client
    )
    assert_equal(response.status_code, 400)
    assert_equal(extract_error_code_from_graphql_error_response(response.json()), ApiErrorCode.LOGIN_REQUIRED.value)
