# Generated by Django 4.0.6 on 2022-10-10 11:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('AppAdmin', '0045_alter_offer_discount_offer_percentage'),
    ]

    operations = [
        migrations.AlterField(
            model_name='offer_discount',
            name='offer_code',
            field=models.CharField(blank=True, max_length=100, null=True, unique=True),
        ),
    ]
