# Generated by Django 4.0.4 on 2022-06-26 17:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('urlscanner', '0004_imageupload'),
    ]

    operations = [
        migrations.AlterField(
            model_name='imageupload',
            name='files',
            field=models.ImageField(upload_to=''),
        ),
    ]
