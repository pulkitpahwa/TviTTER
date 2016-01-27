# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='FueledUser',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=100, null=True, blank=True)),
                ('twitter_username', models.CharField(max_length=50, null=True, blank=True)),
                ('oauth_token', models.CharField(max_length=20, null=True, blank=True)),
                ('oauth_token_secret', models.CharField(max_length=50, null=True, blank=True)),
                ('oauth_verifier', models.CharField(max_length=20, null=True, blank=True)),
            ],
        ),
    ]
