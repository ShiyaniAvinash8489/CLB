# Generated by Django 4.0.6 on 2022-10-17 05:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('AppEndUser', '0010_user_card_details'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user_card_details',
            name='exp_date',
            field=models.CharField(blank=True, max_length=10, null=True),
        ),
    ]
