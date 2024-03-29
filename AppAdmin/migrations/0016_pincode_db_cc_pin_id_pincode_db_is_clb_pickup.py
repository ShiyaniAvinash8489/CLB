# Generated by Django 4.0.6 on 2022-09-23 11:43

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('AppAdmin', '0015_courier_company_review'),
    ]

    operations = [
        migrations.AddField(
            model_name='pincode_db',
            name='CC_Pin_id',
            field=models.ForeignKey(default=1, limit_choices_to={'is_active': True}, on_delete=django.db.models.deletion.CASCADE, related_name='PincodeCCIds', related_query_name='PincodeCCId', to='AppAdmin.couriercompany'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='pincode_db',
            name='is_clb_pickup',
            field=models.BooleanField(default=True),
        ),
    ]
