# Generated by Django 4.0.6 on 2022-08-23 07:06

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('AppEndUser', '0003_initial'),
    ]

    operations = [
        migrations.DeleteModel(
            name='EndUser_Address',
        ),
    ]