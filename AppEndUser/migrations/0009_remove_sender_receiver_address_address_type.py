# Generated by Django 4.0.6 on 2022-09-29 06:38

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('AppEndUser', '0008_rename_user_id_sender_receiver_address_user_idsradd'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='sender_receiver_address',
            name='address_type',
        ),
    ]