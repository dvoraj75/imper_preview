import graphene

from evidenta.core.auth.schema import AuthMutation
from evidenta.core.user.schemas import MeQuery, RoleQuery, UserMutation, UserQuery
from evidenta.core.wallet.schema import WalletMutation, WalletRecordsQuery


class Query(UserQuery, MeQuery, RoleQuery, WalletRecordsQuery, graphene.ObjectType):
    pass


class Mutation(AuthMutation, UserMutation, WalletMutation, graphene.ObjectType):
    pass


schema = graphene.Schema(query=Query, mutation=Mutation)
