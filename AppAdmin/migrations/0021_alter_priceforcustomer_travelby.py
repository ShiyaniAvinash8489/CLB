# Generated by Django 4.0.6 on 2022-09-26 10:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('AppAdmin', '0020_rename_restofinida_priceforcustomer_restofindia'),
    ]

    operations = [
        migrations.AlterField(
            model_name='priceforcustomer',
            name='TravelBy',
            field=models.CharField(choices=[('Air', 'Air'), ('Surface', 'Surface'), ('Air/Surface', 'Air/Surface')], default='Surface', max_length=50),
        ),
    ]
