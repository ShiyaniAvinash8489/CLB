# Generated by Django 4.0.6 on 2022-09-20 09:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('AppAgent', '0010_agent_kyc_userkycimage'),
    ]

    operations = [
        migrations.AddField(
            model_name='agent_bank_details',
            name='is_verify_by',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='agent_kyc',
            name='is_verify_by',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
    ]
