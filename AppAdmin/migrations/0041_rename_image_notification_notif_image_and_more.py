# Generated by Django 4.0.6 on 2022-10-04 11:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('AppAdmin', '0040_notification'),
    ]

    operations = [
        migrations.RenameField(
            model_name='notification',
            old_name='image',
            new_name='Notif_image',
        ),
        migrations.AddField(
            model_name='notification',
            name='usersType',
            field=models.CharField(choices=[('All', 'All'), ('Admin', 'Admin'), ('Agent', 'Agent'), ('EndUser', 'EndUser')], default='All', max_length=50),
        ),
    ]