from graphql_jwt import Refresh
from graphql_jwt.settings import jwt_settings


class RefreshTokenMiddleware:
    def resolve(self, next, root, info, **kwargs):
        auth_token = info.context.COOKIES.get(jwt_settings.JWT_COOKIE_NAME)
        refresh_token = info.context.COOKIES.get(jwt_settings.JWT_REFRESH_TOKEN_COOKIE_NAME)

        if not auth_token and refresh_token:
            new_refresh_token = Refresh.refresh(root, info, refresh_token)
            info.context.COOKIES[jwt_settings.JWT_COOKIE_NAME] = new_refresh_token.token

        return next(root, info, **kwargs)
