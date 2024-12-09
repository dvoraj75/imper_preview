from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import QuerySet

import graphene
from graphene import relay
from graphene_django import DjangoObjectType
from graphene_django.filter import DjangoFilterConnectionField
from graphql import GraphQLResolveInfo
from graphql_relay import from_global_id

from evidenta.common.enums import ApiErrorCode
from evidenta.common.exceptions import PermissionDeniedApiException
from evidenta.common.schemas.utils import (
    login_required,
    permissions_required,
    raise_does_not_exist_error,
    raise_unexpected_error,
    raise_validation_error,
)
from evidenta.core.wallet.models import Wallet, WalletRecord
from evidenta.core.wallet.service import WalletService


class WalletRecordNodeDecrypted(DjangoObjectType):
    class Meta:
        model = WalletRecord
        fields = ("name", "username", "description")
        filter_fields = ("id",)
        interfaces = (relay.Node,)

    decrypted_password = graphene.String()

    def resolve_decrypted_password(self: WalletRecord, info: GraphQLResolveInfo) -> str:
        return Wallet.objects.get_decrypted_record_secret(info.context.user, self)


class WalletRecordNodeEncrypted(DjangoObjectType):
    class Meta:
        model = WalletRecord
        fields = ("name", "username", "description")
        filter_fields = ("id",)
        interfaces = (relay.Node,)


class WalletRecordsQuery(graphene.ObjectType):
    wallet_record = graphene.Field(WalletRecordNodeDecrypted, record_id=graphene.String(required=True))
    wallet_records = DjangoFilterConnectionField(WalletRecordNodeEncrypted)

    @classmethod
    @login_required
    @permissions_required(["view_wallet", "view_walletrecord"])
    def resolve_wallet_records(cls, _, info: GraphQLResolveInfo) -> QuerySet[WalletRecord]:
        return WalletService().get_records(info.context.user)

    @classmethod
    @login_required
    @permissions_required(["view_wallet", "view_walletrecord"])
    def resolve_wallet_record(cls, _, info: GraphQLResolveInfo, record_id: str) -> WalletRecord:
        rec_id = from_global_id(record_id).id
        try:
            return WalletService().get_record(info.context.user, rec_id)
        except WalletRecord.DoesNotExist:
            raise_does_not_exist_error("WalletRecord", {"field": "pk", "value": rec_id})


class WalletRecordsCreate(graphene.relay.ClientIDMutation):
    class Input:
        name = graphene.String(required=True)
        username = graphene.String(required=True)
        secret = graphene.String(required=True)
        description = graphene.String(required=True)

    wallet_record = graphene.Field(WalletRecordNodeEncrypted)

    @classmethod
    @login_required
    @permissions_required(["add_walletrecord"])
    def mutate_and_get_payload(cls, _, info: GraphQLResolveInfo, **kwargs) -> "WalletRecordsCreate":
        try:
            wallet_record = WalletService().create_record(
                info.context.user,
                **kwargs,
            )
            return WalletRecordsCreate(wallet_record=wallet_record)
        except ValidationError as e:
            raise_validation_error(e, "WalletRecord")
        except Exception as e:
            raise_unexpected_error(
                method=f"{cls.__name__}:mutate_and_get_payload",
                original_error=e,
                input_data=kwargs,
                user=info.context.user,
            )


class WalletRecordsUpdate(graphene.relay.ClientIDMutation):
    class Input:
        record_id = graphene.ID(required=True)
        name = graphene.String()
        username = graphene.String()
        secret = graphene.String()
        description = graphene.String()

    wallet_record = graphene.Field(WalletRecordNodeEncrypted)

    @classmethod
    @login_required
    @permissions_required(["change_walletrecord"])
    def mutate_and_get_payload(cls, _, info: GraphQLResolveInfo, record_id: str, **kwargs) -> "WalletRecordsUpdate":
        wallet_record_id = from_global_id(record_id).id
        try:
            wallet_record = WalletService().update_record(info.context.user, wallet_record_id, **kwargs)
            return WalletRecordsUpdate(wallet_record=wallet_record)
        except WalletRecord.DoesNotExist:
            raise_does_not_exist_error("WalletRecord", {"field": "pk", "value": record_id})
        except ValidationError as e:
            raise_validation_error(e, "WalletRecord")
        except Exception as e:
            raise_unexpected_error(
                method=f"{cls.__name__}:mutate_and_get_payload",
                original_error=e,
                input_data=kwargs,
                user=info.context.user,
            )


class WalletRecordsDelete(graphene.relay.ClientIDMutation):
    class Input:
        record_id = graphene.ID(required=True)

    wallet_record = graphene.Field(WalletRecordNodeEncrypted)

    @classmethod
    @login_required
    @permissions_required(["delete_walletrecord"])
    def mutate_and_get_payload(cls, _, info: GraphQLResolveInfo, record_id: str) -> "WalletRecordsDelete":
        wallet_record_id = from_global_id(record_id).id
        try:
            record = WalletService().delete_record(info.context.user, wallet_record_id)
            return WalletRecordsDelete(wallet_record=record)
        except WalletRecord.DoesNotExist:
            raise_does_not_exist_error("WalletRecord", {"field": "pk", "value": record_id})
        except Exception as e:
            raise_unexpected_error(
                method=f"{cls.__name__}:mutate_and_get_payload",
                original_error=e,
                input_data={"pk": record_id},
                user=info.context.user,
            )


class UnlockWalletRecord(graphene.relay.ClientIDMutation):
    class Input:
        user_password = graphene.String(required=True)

    @classmethod
    @login_required
    @permissions_required(["view_wallet"])
    def mutate_and_get_payload(cls, _, info: GraphQLResolveInfo, user_password: str):
        try:
            WalletService().unlock_wallet(info.context.user, user_password)
        except PermissionDenied:
            raise PermissionDeniedApiException(
                "Unable to unlock wallet",
                error_code=ApiErrorCode.PERMISSION_REQUIRED,
            ) from None


class WalletMutation(graphene.ObjectType):
    create_record = WalletRecordsCreate.Field()
    update_record = WalletRecordsUpdate.Field()
    delete_record = WalletRecordsDelete.Field()
    unlock_wallet = UnlockWalletRecord.Field()
