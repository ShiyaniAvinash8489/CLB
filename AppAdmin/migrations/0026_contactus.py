# Generated by Django 4.0.6 on 2022-10-03 05:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('AppAdmin', '0025_faq_cateogry_faq'),
    ]

    operations = [
        migrations.CreateModel(
            name='ContactUs',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50)),
                ('phone', models.CharField(max_length=20)),
                ('email', models.EmailField(max_length=254)),
                ('subject', models.CharField(max_length=50)),
                ('description', models.TextField(max_length=500)),
                ('is_solve', models.BooleanField(default=False)),
                ('solve_timeshtamp', models.DateTimeField()),
                ('solve_by', models.CharField(max_length=50)),
                ('is_active', models.BooleanField(default=True)),
                ('created_on', models.DateTimeField(auto_now_add=True)),
                ('created_by', models.CharField(blank=True, max_length=50, null=True)),
                ('updated_on', models.DateTimeField(auto_now=True)),
                ('updated_by', models.CharField(blank=True, max_length=50, null=True)),
            ],
        ),
    ]