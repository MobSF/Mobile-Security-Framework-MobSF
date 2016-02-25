# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import APITester.models


class Migration(migrations.Migration):

    dependencies = [
        ('APITester', '0003_auto_20160219_1158'),
    ]

    operations = [
        migrations.AlterField(
            model_name='scopeurlsandtests',
            name='SCOPETESTS',
            field=APITester.models.ListField(),
        ),
        migrations.AlterField(
            model_name='scopeurlsandtests',
            name='SCOPEURLS',
            field=APITester.models.ListField(),
        ),
    ]
