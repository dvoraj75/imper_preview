from django.contrib import admin

from evidenta.core.company.models import Company


@admin.register(Company)
class CompanyAdmin(admin.ModelAdmin):
    readonly_fields = ("created", "updated")
    exclude = ()

    fieldsets = (
        ("General", {"fields": ("name", "description", "company_identification_number", "tax_identification_number")}),
        ("Address", {"fields": ("address_1", "address_2", "city", "zip_code")}),
        ("Users", {"fields": ("users",)}),
    )

    add_fieldsets = (
        ("General", {"fields": ("name", "description", "company_identification_number", "tax_identification_number")}),
        ("Address", {"fields": ("address_1", "address_2", "city", "zip_code")}),
        ("Users", {"fields": ("users",)}),
    )

    filter_horizontal = ("users",)
