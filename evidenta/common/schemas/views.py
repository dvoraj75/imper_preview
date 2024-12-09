from graphene_django.views import GraphQLView

from evidenta.common.exceptions import BaseApiException


class CustomGraphQLView(GraphQLView):

    def execute_graphql_request(self, request, data, query, variables, operation_name, show_graphiql=False):
        result = super().execute_graphql_request(request, data, query, variables, operation_name, show_graphiql)

        if result.errors:
            errors = [
                (
                    {
                        "message": e.original_error.message,
                        "error_code": e.original_error.error_code.value,
                        "error_data": e.original_error.error_data,
                    }
                    if isinstance(e.original_error, BaseApiException)
                    else self.format_error(e)
                )
                for e in result.errors
            ]
            result.errors = errors
        return result

    def format_error(self, error):
        if isinstance(error, dict):
            return error
        return super().format_error(error)
