# Generated by Django 4.0.6 on 2022-10-07 09:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('AppAdmin', '0042_banner_offer_discount_alter_notification_body_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='banner',
            old_name='banner_description',
            new_name='banner_caption',
        ),
        migrations.RenameField(
            model_name='banner',
            old_name='banner_name',
            new_name='banner_title',
        ),
        migrations.AddField(
            model_name='offer_discount',
            name='offer_upto_value',
            field=models.IntegerField(blank=True, null=True),
        ),
    ]