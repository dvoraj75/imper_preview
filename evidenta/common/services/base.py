from abc import ABC

from django.db import models


class BaseService(ABC):
    manager: models.Manager

    def create(self, *args, **kwargs) -> models.Model:
        return self.manager.create(*args, **kwargs)

    def get_all(self, *args, **kwargs) -> models.QuerySet[models.Model]:
        return self.manager.get_all(*args, **kwargs)

    def get(self, *args, **kwargs) -> models.Model:
        return self.manager.get(*args, **kwargs)

    def update(self, *args, **kwargs) -> None:
        self.manager.update(*args, **kwargs)

    def delete(self, *args, **kwargs) -> None:
        self.manager.delete(*args, **kwargs)
