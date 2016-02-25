# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('APITester', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='scopeurlsandtests',
            name='MD5',
            field=models.CharField(unique=True, max_length=30),
        ),
    ]
