# Generated by Django 4.0.6 on 2022-08-23 11:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('AppEndUser', '0006_sender_receiver_address_country_code_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='sender_receiver_address',
            name='phone',
            field=models.CharField(max_length=20),
        ),
    ]