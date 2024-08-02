from django.db import models
import base64


# Create your models here.
class Usuario(models.Model):
    nome = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=100)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    criado_em = models.DateTimeField(auto_now_add=True)
    modificado_em = models.DateTimeField(auto_now=True)
    token = models.CharField(max_length=255, default='', blank=True)
    cor_favorita = models.CharField(max_length=7, default='#376b49')

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['nome', 'password']

    class Meta:
        verbose_name = 'usuário'
        verbose_name_plural = 'usuários'
        db_table = 'usuario'
        ordering = ['-criado_em']

    def __str__(self):
        return self.nome

    def get_by_natural_key(self, email):
        return self.get(email=email)

    @property
    def is_anonymous(self):
        return False

    @property
    def is_authenticated(self):
        return True


class Produto(models.Model):
    usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE, related_name='produtos')
    nome = models.CharField(max_length=255)
    descricao = models.TextField(blank=True)
    preco = models.CharField(blank=True, max_length=50)
    quantidade = models.IntegerField()
    criado_em = models.DateTimeField(auto_now_add=True)
    modificado_em = models.DateTimeField(auto_now=True)
    imagem = models.TextField(blank=True, null=True)
    thumbnail = models.TextField(blank=True, null=True)

    class Meta:
        verbose_name = 'produto'
        verbose_name_plural = 'produtos'
        db_table = 'produto'
        ordering = ['nome']

    def __str__(self):
        return self.nome

