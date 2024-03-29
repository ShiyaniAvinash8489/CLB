# Generated by Django 4.0.6 on 2022-09-21 09:43

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('AppAgent', '0015_rename_user_id_agent_address_user_idaddress_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='agent_kyc',
            name='user_idKYC',
            field=models.ForeignKey(blank=True, limit_choices_to={'is_active': True, 'user_type': 'Agent'}, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='AgentKYCUserID', related_query_name='AgentKYCUserID', to=settings.AUTH_USER_MODEL),
        ),
    ]
