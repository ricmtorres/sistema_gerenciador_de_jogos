import hashlib
from django import forms
from django.contrib.auth.hashers import check_password
from django.forms.utils import ErrorList

from gerenciador_jogos.models import Produto, Usuario


class BootStrapModelForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'
            field.widget.attrs['placeholder'] = field.label


class UsuarioForm(BootStrapModelForm):
    class Meta:
        model = Usuario
        fields = ['nome', 'email', 'password']
        widgets = {
            'password': forms.PasswordInput(),
        }


class ProdutoForm(BootStrapModelForm):
    imagem = forms.ImageField(required=False, widget=forms.FileInput(attrs={
        'class': 'form-control',
        'accept': 'image/*',
    }))

    class Meta:
        model = Produto
        fields = ['nome', 'descricao', 'preco', 'quantidade', 'imagem']

        widgets = {
            'preco': forms.TextInput(attrs={'data-mask': '00.000.000,00', 'data-mask-reverse': 'true'}),
        }


class LoginForm(forms.Form):
    email = forms.EmailField(widget=forms.EmailInput(attrs={
        'class': 'form-control my-2', 'placeholder': 'Digite seu email'
    }))
    password = forms.CharField(widget=forms.PasswordInput(attrs={
        'class': 'form-control', 'placeholder': 'Digite sua senha'
    }))

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get('email')
        password = cleaned_data.get('password')

        if email and password:
            try:
                usuario = Usuario.objects.get(email=email)
                hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
                if usuario.password != hashed_password:
                    raise forms.ValidationError('Email ou senha inválidos')
            except Usuario.DoesNotExist:
                raise forms.ValidationError('Email não encontrado')
        return cleaned_data


class MudarSenhaForm(forms.Form):
    old_password = forms.CharField(widget=forms.PasswordInput(attrs={
        'class': 'form-control', 'placeholder': 'Sua senha atual'
    }))
    new_password = forms.CharField(widget=forms.PasswordInput(attrs={
        'class': 'form-control', 'placeholder': 'Nova senha'
    }))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={
        'class': 'form-control', 'placeholder': 'Confirme a nova senha'
    }))

    def __init__(
            self,
            data=None,
            files=None,
            auto_id="id_%s",
            prefix=None,
            initial=None,
            error_class=ErrorList,
            label_suffix=None,
            empty_permitted=False,
            field_order=None,
            use_required_attribute=None,
            renderer=None,
    ):
        super().__init__(data, files, auto_id, prefix, initial, error_class, label_suffix, empty_permitted, field_order,
                         use_required_attribute, renderer)
        self.ValidationError = None

    def clean(self):
        cleaned_data = super().clean()
        old_password = cleaned_data.get('old_password')
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')
        if new_password and confirm_password and new_password != confirm_password:
            print('Confirmação de senha inválida')
            raise forms.ValidationError('Confirmação de senha inválida.')
        if new_password and old_password and new_password == old_password:
            print('A nova senha não pode ser igual à antiga.')
            raise forms.ValidationError('A nova senha não pode ser igual à antiga.')
        return cleaned_data