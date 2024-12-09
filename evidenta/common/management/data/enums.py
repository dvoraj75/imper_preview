from evidenta.core.user.enums import UserRole


BASE_USERS_DATA = (
    {
        "username": val.name.lower(),
        "first_name": val.label,
        "last_name": val.label,
        "role": UserRole(val.value),
        "email": f"{val.name.lower()}@{val.name.lower()}.cz",
    }
    for val in UserRole
)


ROLES_AND_PERMISSIONS = {
    UserRole.GUEST: [
        "change_user",
    ],
    UserRole.CLIENT: [
        "view_company",
        "change_company",
        "view_user",
        "change_user",
    ],
    UserRole.ACCOUNTANT: [
        "view_company",
        "change_company",
        "view_user",
        "change_user",
        "add_walletrecord",
        "change_walletrecord",
        "delete_walletrecord",
        "view_walletrecord",
        "view_wallet",
    ],
    UserRole.SUPERVISOR: [
        "add_company",
        "view_company",
        "change_company",
        "delete_company",
        "add_user",
        "view_user",
        "change_user",
        "delete_user",
        "assign_role",
        "assign_supervisor",
        "assign_company_user",
        "add_walletrecord",
        "change_walletrecord",
        "delete_walletrecord",
        "view_walletrecord",
        "view_wallet",
    ],
    UserRole.ADMIN: [],
}
