# Generated by Django 4.0.6 on 2022-10-04 10:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('AppAdmin', '0038_rename_issue_cat_name_issue_category_catename'),
    ]

    operations = [
        migrations.RenameField(
            model_name='systemanddevicelog',
            old_name='device',
            new_name='device_id',
        ),
        migrations.AddField(
            model_name='systemanddevicelog',
            name='active_fcm',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='systemanddevicelog',
            name='fcm_token',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
        migrations.AlterField(
            model_name='systemanddevicelog',
            name='device_type',
            field=models.CharField(choices=[('android', 'android'), ('ios', 'ios'), ('None', 'None')], default='None', max_length=100),
        ),
    ]
