from unittest.mock import patch

from django.test import Client

import pytest
from graphene_django.utils.testing import graphql_query
from graphql_relay import to_global_id
from pytest import FixtureRequest

from evidenta.common.enums import ApiErrorCode
from evidenta.common.testing.utils import assert_equal, extract_error_code_from_graphql_error_response
from evidenta.core.wallet.models import Wallet
from evidenta.core.wallet.service import WalletService


GET_RECORD_QUERY = """
query getRecord($recordId:String!) {
  walletRecord(recordId:$recordId) {
    name
    username
    description
    decryptedPassword
    id
  }
}
"""

GET_RECORDS_QUERY = """
query getRecords {
  walletRecords {
    edges {
      node {
        name
        username
        description
        id
      }
    }
  }
}
"""


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_wallet_query_get_records__success(django_client: Client, user_fixture: str, request: FixtureRequest) -> None:
    user = request.getfixturevalue(user_fixture)
    django_client.force_login(user)
    ret_value = user.wallet.walletrecord_set.all()
    with patch.object(WalletService, "get_records", return_value=ret_value):
        response = graphql_query(GET_RECORDS_QUERY, operation_name="getRecords", client=django_client)
        assert response.status_code == 200
        assert response.json().get("data")


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["client", "guest"])
def test_wallet_query_get_records__permission_denied(
    django_client: Client, user_fixture: str, request: FixtureRequest
) -> None:
    user = request.getfixturevalue(user_fixture)
    django_client.force_login(user)
    response = graphql_query(GET_RECORDS_QUERY, operation_name="getRecords", client=django_client)
    assert_equal(response.status_code, 400)
    assert_equal(
        extract_error_code_from_graphql_error_response(response.json()), ApiErrorCode.PERMISSION_REQUIRED.value
    )


def test_wallet_query_get_records__not_logged_in(django_client: Client):
    response = graphql_query(GET_RECORDS_QUERY, operation_name="getRecords", client=django_client)
    assert_equal(response.status_code, 400)
    assert_equal(extract_error_code_from_graphql_error_response(response.json()), ApiErrorCode.LOGIN_REQUIRED.value)


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_wallet_query_get_record__success(django_client: Client, user_fixture: str, request: FixtureRequest):
    user = request.getfixturevalue(user_fixture)
    django_client.force_login(user)
    record_data = {"name": "testing", "username": "test", "secret": "secret", "description": "blabla"}
    record = Wallet.objects.create_record(user, **record_data)
    variables = {"recordId": to_global_id("WalletRecord", record.pk)}
    with (
        patch.object(WalletService, "get_record", return_value=user.wallet.walletrecord_set.all()[0]),
        patch.object(WalletService, "get_records", return_value=user.wallet.walletrecord_set.all()),
    ):
        response = graphql_query(
            GET_RECORD_QUERY, operation_name="getRecord", variables=variables, client=django_client
        )
        assert response.status_code == 200
        assert response.json().get("data")


def test_wallet_query_get_record__user_not_logged_in(django_client: Client):
    variables = {"recordId": to_global_id("WalletRecord", "123")}
    response = graphql_query(GET_RECORD_QUERY, operation_name="getRecord", variables=variables, client=django_client)
    assert_equal(response.status_code, 400)
    assert_equal(extract_error_code_from_graphql_error_response(response.json()), ApiErrorCode.LOGIN_REQUIRED.value)


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["client", "guest"])
def test_wallet_query_get_record__permission_denied(
    django_client: Client, user_fixture: str, request: FixtureRequest
) -> None:
    user = request.getfixturevalue(user_fixture)
    django_client.force_login(user)
    variables = {"recordId": to_global_id("WalletRecord", "123")}
    response = graphql_query(GET_RECORD_QUERY, operation_name="getRecord", variables=variables, client=django_client)
    assert_equal(response.status_code, 400)
    assert_equal(
        extract_error_code_from_graphql_error_response(response.json()), ApiErrorCode.PERMISSION_REQUIRED.value
    )


@pytest.mark.django_db
@pytest.mark.parametrize("user_fixture", ["admin", "supervisor", "accountant"])
def test_wallet_query_get_record__wrong_record_id(django_client: Client, user_fixture: str, request: FixtureRequest):
    user = request.getfixturevalue(user_fixture)
    django_client.force_login(user)
    variables = {"recordId": to_global_id("WalletRecord", "123")}
    response = graphql_query(GET_RECORD_QUERY, operation_name="getRecord", variables=variables, client=django_client)
    assert_equal(response.status_code, 400)
    assert_equal(extract_error_code_from_graphql_error_response(response.json()), ApiErrorCode.OBJECT_NOT_FOUND.value)
