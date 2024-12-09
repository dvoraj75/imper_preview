from urllib.parse import urljoin


def create_url(base: str, resource_path, **kwargs) -> str:
    if kwargs:
        resource_path = resource_path.format(**kwargs)
    return urljoin(base, resource_path)
