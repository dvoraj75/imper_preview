import graphene
from api.common.utils import login_required, permissions_required
from api.models import Company
from graphene_django.filter.fields import DjangoFilterConnectionField
from graphene_django.types import DjangoObjectType
from graphql_relay import from_global_id


class CompanyNode(DjangoObjectType):
    class Meta:
        model = Company
        filter_fields = {
            "name": ["exact", "icontains", "istartswith"],
            "company_identification_number": ["exact"],
            "tax_identification_number": ["exact"],
        }
        interfaces = (graphene.relay.Node,)

    pk = graphene.Int()

    @classmethod
    @login_required
    @permissions_required(["api.view_company"])
    def get_queryset(cls, company_manager, info):
        return company_manager.get_all_related_users(as_user=info.context.user)


class CompanyQuery(graphene.ObjectType):
    company = graphene.relay.Node.Field(CompanyNode)
    companies = DjangoFilterConnectionField(CompanyNode)


class CreateCompany(graphene.relay.ClientIDMutation):
    """
    Create company mutation for Company model
    """

    class Input:
        name = graphene.String(required=True)
        description = graphene.String()
        company_identification_number = graphene.String(required=True)
        tax_identification_number = graphene.String()
        users = graphene.List(graphene.ID)

    company = graphene.Field(CompanyNode)

    # pylint: disable=unused-argument
    @classmethod
    @login_required
    @permissions_required(["api.add_company"])
    def mutate_and_get_payload(cls, root, info, **kwargs):
        """
        Create company and return payload (created company and other information).
        Permissions:
            api.can_create_company
        """
        return CreateCompany(company=Company.objects.create_company(**kwargs))


class UpdateCompany(graphene.relay.ClientIDMutation):
    """
    Update company mutation for Company model
    """

    class Input:
        company_id = graphene.ID(required=True)
        name = graphene.String()
        description = graphene.String()
        company_identification_number = graphene.String()
        tax_identification_number = graphene.String()
        users = graphene.List(graphene.ID)

    company = graphene.Field(CompanyNode)

    # pylint: disable=unused-argument
    @classmethod
    @login_required
    @permissions_required(["api.change_company"])
    def mutate_and_get_payload(cls, root, info, company_id, **kwargs):
        """
        Update company with given company_id and return payload (updated company and other information).
        """
        Company.objects.update_user(
            company_id=from_global_id(company_id).id or company_id,
            as_user=info.context.user,
            **kwargs,
        )
        return UpdateCompany()


class DeleteCompany(graphene.relay.ClientIDMutation):
    """
    Delete company mutation for Company model
    """

    class Input:
        company_id = graphene.ID()

    # pylint: disable=unused-argument
    @classmethod
    @login_required
    @permissions_required(["api.delete_company"])
    def mutate_and_get_payload(cls, root, info, company_id):
        """
        Delete company with give company_id
        Permissions:
            api.can_delete_company
        """
        Company.objects.delete_company(
            company_id=(from_global_id(company_id).id or company_id),
            as_user=info.context.user,
        )
        return DeleteCompany()


class CompanyMutation(graphene.ObjectType):
    """
    All graphql mutations for company
    """

    create_company = CreateCompany.Field()
    update_company = UpdateCompany.Field()
    delete_company = DeleteCompany.Field()
