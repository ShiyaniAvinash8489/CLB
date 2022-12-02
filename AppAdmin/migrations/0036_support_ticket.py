# Generated by Django 4.0.6 on 2022-10-04 04:21

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('AppAdmin', '0035_delete_support_ticket'),
    ]

    operations = [
        migrations.CreateModel(
            name='Support_Ticket',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ticket_no', models.CharField(blank=True, max_length=50, null=True, unique=True)),
                ('country_code', models.CharField(blank=True, max_length=10, null=True)),
                ('requester_phone', models.CharField(blank=True, max_length=20, null=True)),
                ('requester_email', models.EmailField(blank=True, max_length=254, null=True)),
                ('subject', models.CharField(blank=True, max_length=50, null=True)),
                ('description', models.TextField(blank=True, max_length=500, null=True)),
                ('order_id', models.CharField(blank=True, max_length=20, null=True)),
                ('is_closed', models.BooleanField(blank=True, default=False, null=True)),
                ('closing_details', models.TextField(blank=True, max_length=500, null=True)),
                ('closed_by', models.CharField(blank=True, max_length=50, null=True)),
                ('closing_timestamp', models.DateTimeField(blank=True, null=True)),
                ('status', models.CharField(choices=[('Open', 'Open'), ('In_Progress', 'In_Progress'), ('Closed', 'Closed'), ('Reopen', 'Reopen')], default='Open', max_length=50)),
                ('is_active', models.BooleanField(default=True)),
                ('created_on', models.DateTimeField(auto_now_add=True)),
                ('created_by', models.CharField(blank=True, max_length=50, null=True)),
                ('updated_on', models.DateTimeField(auto_now=True)),
                ('updated_by', models.CharField(blank=True, max_length=50, null=True)),
                ('client_User_Id', models.ForeignKey(blank=True, limit_choices_to={'is_active': True}, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='ClientUserIds', related_query_name='ClientUserId', to=settings.AUTH_USER_MODEL)),
                ('issue_Cate_id', models.ForeignKey(blank=True, limit_choices_to={'is_active': True}, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='IssueCateIds', related_query_name='IssueCateId', to='AppAdmin.issue_category')),
            ],
        ),
    ]
