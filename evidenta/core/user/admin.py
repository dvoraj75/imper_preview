from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _

from evidenta.core.user.models.user import Role, User


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    readonly_fields = ("created", "updated", "last_login")
    exclude = ()

    fieldsets = (
        (_("General"), {"fields": ("username", "role", "created", "updated", "last_login")}),
        (_("Personal Info"), {"fields": ("title", "first_name", "last_name", "gender", "birthday")}),
        (_("Contact info"), {"fields": ("phone_number", "email")}),
        (_("Permissions"), {"fields": ("user_permissions",)}),
    )

    add_fieldsets = (
        (_("General"), {"fields": ("username", "password1", "password2", "role")}),
        (_("Personal Info"), {"fields": ("title", "first_name", "last_name", "gender", "birthday")}),
        (_("Contact info"), {"fields": ("phone_number", "email")}),
        (_("Permissions"), {"fields": ("user_permissions",)}),
    )

    filter_horizontal = ("user_permissions",)


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    fieldsets = (
        (_("General"), {"fields": ("role",)}),
        (_("Permissions"), {"fields": ("permissions",)}),
    )

    add_fieldsets = (
        (_("General"), {"fields": ("role",)}),
        (_("Permissions"), {"fields": ("permissions",)}),
    )

    filter_horizontal = ("permissions",)
