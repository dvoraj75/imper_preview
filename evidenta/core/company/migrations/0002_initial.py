from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("company", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="company",
            name="users",
            field=models.ManyToManyField(blank=True, related_name="companies", to=settings.AUTH_USER_MODEL),
        ),
    ]
