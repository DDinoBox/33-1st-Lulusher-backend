# Generated by Django 4.0.4 on 2022-05-31 10:49

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0003_alter_cart_created_at_alter_cart_updated_at_and_more'),
    ]

    operations = [
        migrations.DeleteModel(
            name='Cart',
        ),
    ]