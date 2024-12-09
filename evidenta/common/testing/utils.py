import datetime
import re
import secrets
import string
from typing import Any

from django.db import models

from evidenta.common.enums import ApiErrorCode
from evidenta.common.schemas.utils import get_error_message_from_error_code
from evidenta.core.user.enums import UserGender, UserRole


def assert_exists(model: type[models.Model], **model_data) -> None:
    assert model.objects.filter(**model_data).exists()


def assert_obj_with_dict(
    obj: models.Model, obj_dict: dict[str, Any], extra: dict[str, Any] | None = None, exclude: tuple[str, ...] = tuple()
) -> None:
    if extra:
        obj_dict.update(extra)
    for key, value in obj_dict.items():
        if key in exclude:
            continue
        assert getattr(obj, key) == value


def assert_obj_equal(obj_1: models.Model, obj_2: models.Model, excluded: tuple[str, ...] = ("updated",)) -> None:
    assert len(obj_1._meta.fields) == len(obj_2._meta.fields) and all(
        (
            getattr(obj_1, obj_1_field.name) == getattr(obj_2, obj_2_field.name)
            for obj_1_field, obj_2_field in zip(obj_1._meta.fields, obj_2._meta.fields, strict=False)
            if obj_1_field.name not in excluded
        )
    )


def assert_obj_not_equal(obj_1: models.Model, obj_2: models.Model, excluded: tuple[str, ...] = ("updated",)) -> None:
    if len(obj_1._meta.fields) != len(obj_2._meta.fields):
        return
    assert len(obj_1._meta.fields) != len(obj_2._meta.fields) or not all(
        (
            getattr(obj_1, obj_1_field.name) == getattr(obj_2, obj_2_field.name)
            for obj_1_field, obj_2_field in zip(obj_1._meta.fields, obj_2._meta.fields, strict=False)
            if obj_1_field.name not in excluded
        )
    )


def assert_count(qs: models.QuerySet[models.Model], count: int) -> None:
    assert qs.count() == count


def assert_pk(obj_1: models.Model, obj_2: models.Model) -> None:
    assert obj_1.pk == obj_2.pk


def assert_none(value: Any) -> None:
    assert value is None


def assert_equal(value_1: Any, value_2: Any) -> None:
    assert value_1 == value_2


def assert_exist(value: Any) -> None:
    assert value


def assert_match(regex: str, value: str) -> None:
    assert re.match(regex, value)


def assert_error_code(response: dict[str, Any], error_code: ApiErrorCode) -> None:
    for error in response["errors"]:
        assert_equal(error.get("error_code"), error_code)


def assert_error_message(response: dict[str, Any], error_code: ApiErrorCode, error: Exception) -> None:
    for e in response.get("errors"):
        assert_equal(get_error_message_from_error_code(error_code, error=str(error)), e.get("message"))


def assert_match_error_message(response: dict[str, Any], error_regex: str) -> None:
    for e in response.get("errors"):
        assert_match(error_regex, e.get("message"))


def generate_random_password() -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(alphabet) for _ in range(12))


def generate_company_identification_number() -> str:
    partial_number = "".join(secrets.choice(string.digits) for _ in range(7))
    sum_value = 0
    for i, weight in zip(range(7), range(8, 1, -1), strict=False):
        sum_value += int(partial_number[i]) * weight
    control_digit = (11 - (sum_value % 11)) % 10
    return partial_number + str(control_digit)


def generate_birth_number() -> str:
    year = secrets.choice(range(1900, 2024))
    month = secrets.choice(range(1, 13))
    day = secrets.choice(range(1, 29))

    if secrets.choice([True, False]):
        month += 50

    date_part = f"{year % 100:02}{month:02}{day:02}"

    suffix = secrets.choice(range(0, 1000))

    if year >= 1954:
        base_number = int(date_part) * 1000 + suffix
        control_digit = base_number % 11
        if control_digit == 10:
            control_digit = 0
        return f"{date_part}/{suffix:03}{control_digit}"
    else:
        return f"{date_part}/{suffix:03}"


def generate_random_user_data() -> dict[str, any]:
    random_number = secrets.randbelow(1000000)
    return {
        "username": f"JohnDoe{random_number}",
        "password": generate_random_password(),
        "title": "Doc.",
        "first_name": f"John{random_number}",
        "last_name": f"Doe{random_number}",
        "email": f"john.doe_{random_number}@test.cz",
        "role": UserRole.GUEST,
        "phone_number": "0123456789",
        "gender": secrets.choice([UserGender.MALE, UserGender.FEMALE]),
        "birthday": datetime.date(1970, 1, 1),
    }


def generate_random_company_data() -> dict[str, any]:
    identification_number = generate_company_identification_number()
    return {
        "name": "John Doe's drink etc.",
        "description": "The biggest producer of unhealthy drinks!!",
        "company_identification_number": identification_number,
        "tax_identification_number": f"CZ{identification_number}",
        "address_1": "Top street 76",
        "address_2": "",
        "city": "Evidenta Hill",
        "zip_code": "12345",
    }


def extract_nodes_from_graphql_response(response: dict[str, Any]) -> list[dict[str, Any]]:
    for value in response.get("data", {}).values():
        if isinstance(value, dict) and "edges" in value:
            return [edge["node"] for edge in value["edges"]]
    return []


def extract_error_code_from_graphql_error_response(response: dict[str, Any]) -> str:
    for error in response.get("errors", []):
        return error.get("error_code")


def extract_message_from_graphql_error_response(response: dict[str, Any]) -> str:
    for error in response.get("errors", []):
        return error.get("message")


def generate_mutation(mutation: str, **input) -> str:
    mutation_template = """
    mutation {mutation} {{
      {mutation}(input: {{
        {input}
      }}) {{
        clientMutationId
      }}
    }}
    """
    # fmt: off
    input_str = " ".join([f'{key}: {f"\"{val}\"" if isinstance(val, str) else val}' for key, val in input.items()])
    # fmt: on
    return mutation_template.format(mutation=mutation, input=input_str)


def generate_all_query(query_name: str, attrs: list[str]) -> str:
    query_template = """
    query {query_name} {{
      {query_name} {{
        edges {{
          node {{
            {attrs}
          }}
        }}
      }}
    }}
    """
    return query_template.format(query_name=query_name, attrs=", ".join(attrs))


def generate_query(node_name: str, attrs: list[str], **input) -> str:
    query_template = """
    query {node_name} {{
      {node_name} ({input_str}) {{
        {attrs}
      }}
    }}
    """
    return query_template.format(
        node_name=node_name,
        attrs=", ".join(attrs),
        # fmt: off
        input_str=", ".join([f'{key}: {f"\"{val}\"" if isinstance(val, str) else val}' for key, val in input.items()])
        # fmt: on
    )
