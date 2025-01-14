# Generated by Django 4.2.14 on 2024-08-19 15:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("user", "0002_role_created_role_updated"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="role",
            name="name",
        ),
        migrations.AddField(
            model_name="role",
            name="role",
            field=models.PositiveSmallIntegerField(
                choices=[
                    ("GUEST", "Guest"),
                    ("CLIENT", "Client"),
                    ("ACCOUNTANT", "Accountant"),
                    ("SUPERVISOR", "Supervisor"),
                    ("ADMIN", "Admin"),
                ],
                null=True,
                unique=True,
            ),
        ),
    ]
