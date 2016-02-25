# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='ScopeURLSandTests',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('MD5', models.CharField(max_length=30)),
                ('SCOPEURLS', models.TextField()),
                ('SCOPETESTS', models.TextField()),
            ],
        ),
    ]
