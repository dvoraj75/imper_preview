"""evidenta URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.conf import settings
from django.conf.urls.i18n import i18n_patterns
from django.contrib import admin
from django.urls import path, re_path
from django.views.decorators.csrf import csrf_exempt

from graphql_jwt.decorators import jwt_cookie

from evidenta.common.schemas.views import CustomGraphQLView


urlpatterns = [
    re_path(r"^api/?$", jwt_cookie(csrf_exempt(CustomGraphQLView.as_view(graphiql=settings.DEBUG)))),
]

if settings.DEBUG:
    urlpatterns += i18n_patterns(path("admin", admin.site.urls))
