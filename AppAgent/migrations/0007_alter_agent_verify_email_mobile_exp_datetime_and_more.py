# Generated by Django 4.0.6 on 2022-09-07 11:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('AppAgent', '0006_agent_verify_email_mobile'),
    ]

    operations = [
        migrations.AlterField(
            model_name='agent_verify_email_mobile',
            name='exp_datetime',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='agent_verify_email_mobile',
            name='otp',
            field=models.CharField(blank=True, max_length=7, null=True),
        ),
    ]
