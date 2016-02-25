# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('APITester', '0002_auto_20160219_1153'),
    ]

    operations = [
        migrations.AlterField(
            model_name='scopeurlsandtests',
            name='MD5',
            field=models.CharField(max_length=30),
        ),
    ]
