from django.core.management.base import BaseCommand

from evidenta.common.management.data.init_data import create_base_data


class Command(BaseCommand):
    def handle(self, *args, **options):
        create_base_data()
