from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import Client

import pytest
from graphene_django.utils.testing import graphql_query
from pytest import FixtureRequest

from evidenta.common.enums import ApiErrorCode
from evidenta.common.testing.utils import assert_equal, extract_error_code_from_graphql_error_response
from evidenta.core.wallet.models import Wallet
from evidenta.core.wallet.service import WalletService


CREATE_RECORD_MUTATION = """
mutation createWalletRecord($createWalletRecordInput:WalletRecordsCreateInput!) {
  createRecord(input:$createWalletRecordInput) {
    walletRecord {
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
def test_create_wallet_record__success(django_client: Client, user_fixture: str, request: FixtureRequest):
    user = request.getfixturevalue(user_fixture)
    django_client.force_login(user)
    record_data = {"name": "testing", "username": "test", "secret": "secret", "description": "blabla"}
    variables = {"createWalletRecordInput": record_data}
    record = Wallet.objects.create_record(user, **record_data)
    with patch.object(WalletService, "create_record", return_value=record) as mock_create_record:
        response = graphql_query(
            CREATE_RECORD_MUTATION, operation_name="createWalletRecord", variables=variables, client=django_client
        )
        mock_create_record.assert_called_once_with(user, **variables["createWalletRecordInput"])
        assert response.status_code == 200
        assert response.json().get("data")


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["client", "guest"])
def test_create_wallet_record__permission_denied(django_client: Client, user_fixture: str, request: FixtureRequest):
    user = request.getfixturevalue(user_fixture)
    django_client.force_login(user)
    record_data = {"name": "testing", "username": "test", "secret": "secret", "description": "blabla"}
    variables = {"createWalletRecordInput": record_data}
    response = graphql_query(
        CREATE_RECORD_MUTATION, operation_name="createWalletRecord", variables=variables, client=django_client
    )
    assert_equal(response.status_code, 400)
    assert_equal(
        extract_error_code_from_graphql_error_response(response.json()), ApiErrorCode.PERMISSION_REQUIRED.value
    )


@pytest.mark.django_db
@pytest.mark.parametrize(
    "effect", [ValidationError("wrong data"), ValueError("too long salt"), AttributeError("something went wrong")]
)
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_create_wallet_record__fail(
    django_client: Client, effect: Exception, user_fixture: str, request: FixtureRequest
):
    user = request.getfixturevalue(user_fixture)
    django_client.force_login(user)
    record_data = {"name": "testing", "username": "test", "secret": "secret", "description": "blabla"}
    variables = {"createWalletRecordInput": record_data}
    with patch.object(WalletService, "create_record", side_effect=effect):
        response = graphql_query(
            CREATE_RECORD_MUTATION, operation_name="createWalletRecord", variables=variables, client=django_client
        )
        assert response.status_code == 400
        assert response.json().get("errors")


def test_create_wallet_record__user_logged_out(django_client: Client):
    record_data = {"name": "testing", "username": "test", "secret": "secret", "description": "blabla"}
    variables = {"createWalletRecordInput": record_data}
    response = graphql_query(
        CREATE_RECORD_MUTATION, operation_name="createWalletRecord", variables=variables, client=django_client
    )
    assert_equal(response.status_code, 400)
    assert_equal(extract_error_code_from_graphql_error_response(response.json()), ApiErrorCode.LOGIN_REQUIRED.value)
