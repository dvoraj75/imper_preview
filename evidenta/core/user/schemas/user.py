from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db.models import QuerySet

import django_filters
import graphene
from graphene import ResolveInfo
from graphene_django.filter.fields import DjangoFilterConnectionField
from graphene_django.types import DjangoObjectType
from graphql_relay import from_global_id

from evidenta.common.exceptions import ObjectDoesNotExist
from evidenta.common.schemas.utils import (
    check_if_user_can_assign_companies,
    check_if_user_can_assign_role,
    login_required,
    permissions_required,
    raise_does_not_exist_error,
    raise_unexpected_error,
    raise_validation_error,
)
from evidenta.core.user.models import User
from evidenta.core.user.service import UserService


class UserFilter(django_filters.FilterSet):
    order_by = django_filters.OrderingFilter(
        fields=(
            ("username", "username"),
            ("first_name", "first_name"),
            ("last_name", "last_name"),
            ("email", "email"),
            ("role__role", "role"),
        )
    )

    username = django_filters.CharFilter(field_name="username", lookup_expr="iexact")
    username_contains = django_filters.CharFilter(field_name="username", lookup_expr="icontains")
    username_startswith = django_filters.CharFilter(field_name="username", lookup_expr="istartswith")

    first_name = django_filters.CharFilter(field_name="first_name", lookup_expr="iexact")
    first_name_contains = django_filters.CharFilter(field_name="first_name", lookup_expr="icontains")
    first_name_startswith = django_filters.CharFilter(field_name="first_name", lookup_expr="istartswith")

    last_name = django_filters.CharFilter(field_name="last_name", lookup_expr="iexact")
    last_name_contains = django_filters.CharFilter(field_name="last_name", lookup_expr="icontains")
    last_name_startswith = django_filters.CharFilter(field_name="last_name", lookup_expr="istartswith")

    email = django_filters.CharFilter(field_name="email", lookup_expr="iexact")
    email_contains = django_filters.CharFilter(field_name="email", lookup_expr="icontains")
    email_startswith = django_filters.CharFilter(field_name="email", lookup_expr="istartswith")

    phone_number = django_filters.CharFilter(field_name="phone_number", lookup_expr="iexact")
    phone_number_contains = django_filters.CharFilter(field_name="phone_number", lookup_expr="icontains")
    phone_number_startswith = django_filters.CharFilter(field_name="phone_number", lookup_expr="icontains")

    role = django_filters.CharFilter(field_name="role__role", lookup_expr="iexact")

    class Meta:
        model = get_user_model()
        fields = {
            "username": ["iexact", "icontains", "istartswith"],
            "first_name": ["iexact", "icontains", "istartswith"],
            "last_name": ["iexact", "icontains", "istartswith"],
            "email": ["iexact", "icontains", "istartswith"],
            "phone_number": ["iexact", "icontains", "istartswith"],
            "role__role": ["iexact"],
        }


class UserNode(DjangoObjectType):
    class Meta:
        model = get_user_model()
        exclude = ["password", "is_superuser", "is_staff"]
        interfaces = (graphene.relay.Node,)

    pk = graphene.Int()

    @classmethod
    @login_required
    @permissions_required(["user.view_user"])
    def get_queryset(cls, _, info: ResolveInfo) -> QuerySet[User]:
        try:
            return UserService().get_all_related(as_user=info.context.user)
        except Exception as e:
            raise_unexpected_error(
                method="UserNode:get_queryset",
                input_data=None,
                user=info.context.user,
                original_error=e,
            )

    @classmethod
    @login_required
    @permissions_required(["user.view_user"])
    def get_user(cls, user_id: str, info: ResolveInfo) -> User:
        try:
            return UserService().get_from_related(as_user=info.context.user, pk=user_id)
        except ObjectDoesNotExist:
            raise_does_not_exist_error("User", {"field": "pk", "value": user_id})
        except Exception as e:
            raise_unexpected_error(
                method="UserNode:get_user",
                input_data={"user_id": user_id},
                user=info.context.user,
                original_error=e,
            )

    @classmethod
    def get_node(cls, info: ResolveInfo, id: str) -> User:
        return cls.get_user(id, info)


class UserQuery(graphene.ObjectType):
    user = graphene.relay.Node.Field(UserNode)
    users = DjangoFilterConnectionField(UserNode, filterset_class=UserFilter)


class MeQuery(graphene.ObjectType):
    me = graphene.Field(UserNode)

    @classmethod
    @login_required
    def resolve_me(cls, _, info: ResolveInfo) -> User:
        return info.context.user


class CreateUser(graphene.relay.ClientIDMutation):
    class Input:
        username = graphene.String(required=True)
        title = graphene.String()
        first_name = graphene.String(required=True)
        last_name = graphene.String(required=True)
        email = graphene.String(required=True)
        role = graphene.Int(required=True)
        phone_number = graphene.String()
        gender = graphene.Int()
        birthday = graphene.Date()
        companies = graphene.List(graphene.ID)

    user = graphene.Field(UserNode)

    @classmethod
    @login_required
    @permissions_required(["user.add_user"])
    def mutate_and_get_payload(cls, _, info: ResolveInfo, **kwargs) -> "CreateUser":
        if kwargs.get("companies"):
            check_if_user_can_assign_companies(info.context.user)
        check_if_user_can_assign_role(info.context.user, kwargs.get("role"))
        try:
            return CreateUser(user=UserService().create(**kwargs))
        except ValidationError as e:
            raise_validation_error(e, obj_name="User")
        except Exception as e:
            raise_unexpected_error(
                method="CreateUser:mutate_and_get_payload",
                input_data=kwargs,
                user=info.context.user,
                original_error=e,
            )


class UpdateUser(graphene.relay.ClientIDMutation):
    class Input:
        user_id = graphene.ID(required=True)
        username = graphene.String()
        title = graphene.String()
        first_name = graphene.String()
        last_name = graphene.String()
        email = graphene.String()
        role = graphene.Int()
        phone_number = graphene.String()
        gender = graphene.Int()
        birthday = graphene.Date()
        companies = graphene.List(graphene.ID)

    @classmethod
    @login_required
    @permissions_required(["user.change_user"])
    def mutate_and_get_payload(cls, _, info: ResolveInfo, user_id: str, **kwargs) -> "UpdateUser":
        _user_id = from_global_id(user_id).id
        if "companies" in kwargs:
            check_if_user_can_assign_companies(info.context.user)

        if "role" in kwargs:
            check_if_user_can_assign_role(info.context.user, kwargs.get("role"))

        try:
            UserService().update(user_id=_user_id, as_user=info.context.user, **kwargs)
        except ObjectDoesNotExist:
            raise_does_not_exist_error("User", {"field": "pk", "value": user_id})
        except ValidationError as e:
            raise_validation_error(e, obj_name="User")
        except Exception as e:
            raise_unexpected_error(
                method="UpdateUser:mutate_and_get_payload",
                input_data={"id": user_id, **kwargs},
                user=info.context.user,
                original_error=e,
            )
        return UpdateUser()


class DeleteUser(graphene.relay.ClientIDMutation):
    class Input:
        user_id = graphene.ID()

    @classmethod
    @login_required
    @permissions_required(["user.delete_user"])
    def mutate_and_get_payload(cls, _, info: ResolveInfo, user_id: str) -> "DeleteUser":
        _user_id = from_global_id(user_id).id
        try:
            UserService().delete(user_id=_user_id, as_user=info.context.user)
        except ObjectDoesNotExist:
            raise_does_not_exist_error("User", {"field": "pk", "value": user_id})
        except Exception as e:
            raise_unexpected_error(
                method="DeleteUser:mutate_and_get_payload",
                input_data={"id": user_id},
                user=info.context.user,
                original_error=e,
            )
        return DeleteUser()


class UserMutation(graphene.ObjectType):
    create_user = CreateUser.Field()
    update_user = UpdateUser.Field()
    delete_user = DeleteUser.Field()
