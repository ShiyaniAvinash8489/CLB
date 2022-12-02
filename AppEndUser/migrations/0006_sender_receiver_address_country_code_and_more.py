# Generated by Django 4.0.6 on 2022-08-23 10:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('AppEndUser', '0005_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='sender_receiver_address',
            name='country_code',
            field=models.CharField(default='+91', max_length=50),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='sender_receiver_address',
            name='phone',
            field=models.CharField(default='589', max_length=20, unique=True),
            preserve_default=False,
        ),
    ]
