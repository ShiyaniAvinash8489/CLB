# Generated by Django 4.0.6 on 2022-09-05 06:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('AppAdmin', '0006_bookingslot'),
    ]

    operations = [
        migrations.AddField(
            model_name='pincode_db',
            name='is_delivery',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='pincode_db',
            name='is_pickup',
            field=models.BooleanField(default=True),
        ),
    ]
