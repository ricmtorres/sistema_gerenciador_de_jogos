# Generated by Django 5.0.6 on 2024-08-02 23:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('gerenciador_jogos', '0002_rename_is_ativo_usuario_is_active'),
    ]

    operations = [
        migrations.AddField(
            model_name='usuario',
            name='cor_favorita',
            field=models.CharField(default='#376b49', max_length=7),
        ),
    ]
