from django.db import models

from api.common.model_utils import CommonModel, Level
from api.common.utils import check_choices
from api.models.user import User


class Note(CommonModel):
    # Main note attributes
    header = models.CharField(max_length=100, blank=True, default="")
    text = models.TextField(blank=False, null=False, default=None)
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name="notes")
    level = models.PositiveSmallIntegerField(
        choices=Level.choices,
        null=False,
        blank=False,
        default=None,
    )

    def __str__(self) -> str:
        return self.header or self.text[:10]

    @check_choices((("level", Level.choices),))
    def save(self, *args, **kwargs):
        # Check text for empty string
        if not self.text:
            raise ValueError("Text cannot be empty")
        super().save(*args, **kwargs)

    class Meta:
        verbose_name_plural = "Notes"
