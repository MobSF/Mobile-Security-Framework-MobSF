#!/usr/bin/env python3
"""Generate an inventory of Django REST Framework endpoints."""

import json
from importlib import import_module
from pathlib import Path

import django
from django.conf import settings
from django.core.management import call_command


def main() -> None:
    django.setup()
    data_file = Path("docs/security/reports/api_inventory.json")
    data_file.parent.mkdir(parents=True, exist_ok=True)
    with data_file.open("w", encoding="utf-8") as handle:
        call_command("show_urls", format="json", stdout=handle)


if __name__ == "__main__":
    main()
