# Generated by Django 5.0.6 on 2024-06-17 11:47

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Packet',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField()),
                ('src_ip', models.GenericIPAddressField()),
                ('dst_ip', models.GenericIPAddressField()),
                ('protocol', models.CharField(max_length=10)),
                ('length', models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='Prediction',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('is_attack', models.BooleanField()),
                ('attack_type', models.CharField(blank=True, max_length=50, null=True)),
                ('packet', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='ids_app.packet')),
            ],
        ),
    ]
