# Generated by Django 4.0.6 on 2022-09-20 12:14

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('AppAgent', '0012_remove_agent_kyc_user_id_agent_kyc_user_idkyc'),
    ]

    operations = [
        migrations.RenameField(
            model_name='agent_kyc',
            old_name='user_idKYC',
            new_name='user_id',
        ),
    ]