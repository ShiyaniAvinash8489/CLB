# Generated by Django 4.0.6 on 2022-10-17 11:39

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('AppEndUser', '0013_end_user_order_awb_no'),
    ]

    operations = [
        migrations.RenameField(
            model_name='end_user_order',
            old_name='company_name',
            new_name='company_name_id',
        ),
    ]