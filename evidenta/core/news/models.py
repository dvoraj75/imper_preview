from django.db import models

from api.common.model_utils import CommonModel, Level
from api.common.utils import check_choices
from api.models.user import User


class News(CommonModel):
    header = models.CharField(max_length=100, default=None)
    text = models.TextField(default=None)
    author = models.ForeignKey(User, related_name="news", on_delete=models.CASCADE)
    level = models.PositiveSmallIntegerField(choices=Level.choices, blank=True, default=Level.MEDIUM)

    @check_choices((("level", Level.choices),))
    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

    def get_level_name(self):
        return self.get_level_display()

    def __str__(self):
        return self.header

    class Meta:
        verbose_name_plural = "News"
