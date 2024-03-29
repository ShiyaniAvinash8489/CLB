# Generated by Django 4.0.6 on 2022-09-20 12:22

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('AppAgent', '0014_rename_user_id_agent_kyc_user_idkyc'),
    ]

    operations = [
        migrations.RenameField(
            model_name='agent_address',
            old_name='user_id',
            new_name='user_idAddress',
        ),
        migrations.RemoveField(
            model_name='agent_bank_details',
            name='user_id',
        ),
        migrations.AddField(
            model_name='agent_bank_details',
            name='user_idBank',
            field=models.ForeignKey(default='99', limit_choices_to={'is_active': True, 'user_type': 'Agent'}, on_delete=django.db.models.deletion.CASCADE, related_query_name='AgentBankUserID', to=settings.AUTH_USER_MODEL),
            preserve_default=False,
        ),
    ]
