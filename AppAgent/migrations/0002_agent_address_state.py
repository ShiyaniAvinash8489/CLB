# Generated by Django 4.0.6 on 2022-09-06 10:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('AppAgent', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='agent_address',
            name='state',
            field=models.CharField(default='a', max_length=50),
            preserve_default=False,
        ),
    ]