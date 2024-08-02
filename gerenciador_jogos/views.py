import base64
import hashlib

from PIL import Image
import io

from django.contrib import messages
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ImproperlyConfigured
from django.core.mail import send_mail
from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

from gerenciador_jogos.models import Usuario, Produto

from django.db.models import Count, Q

from .token_utils import generate_token

from .forms import UsuarioForm, ProdutoForm, LoginForm, MudarSenhaForm


# view para ADMIN

def listar_usuarios(request):
    usuario_id = request.session.get('usuario_id')
    if usuario_id:
        usuario = Usuario.objects.defer('password').get(id=usuario_id)
        if usuario.is_admin:
            query = request.GET.get('q')
            status = request.GET.get('status')
            data_criado = request.GET.get('data_criado')
            usuarios = Usuario.objects.defer('password').all()

            if query:
                usuarios = usuarios.filter(Q(nome__icontains=query) | Q(email__icontains=query))

            if status:
                is_ativo = True if status == 'ativo' else False
                usuarios = usuarios.filter(is_ativo=is_ativo)

            usuarios = usuarios.filter(is_admin=False).annotate(
                estoque_produtos=Count('produtos'))
            return render(request, 'usuarios/listar_usuarios.html', {'usuarios': usuarios})
        else:
            messages.error(request, 'Você não tem permissão para acessar essa página.')
            return redirect('dashboard')
    else:
        return redirect('login')


def desativar_usuario(request, usuario_id):
    try:
        sessao_id = request.session.get('usuario_id')
        sessao = Usuario.objects.get(id=sessao_id)
        if sessao:
            usuario_a_desativar = get_object_or_404(Usuario, id=usuario_id)
            if sessao.is_admin:
                usuario_a_desativar.is_active = False
                usuario_a_desativar.save()
                messages.success(request, 'Usuário desativado com sucesso.')
            else:
                messages.error(request, 'Você não tem permissão para desativar usuários.')
                return redirect('dashboard')
            return redirect('listar_usuarios')
        else:
            return redirect('login')
    except Usuario.DoesNotExist:
        messages.error(request, 'Usuário não encontrado.')
        return redirect('listar_usuarios')


def reativar_usuario(request, usuario_id):
    try:
        sessao_id = request.session.get('usuario_id')
        sessao = Usuario.objects.get(id=sessao_id)
        if sessao:
            usuario_a_desativar = get_object_or_404(Usuario, id=usuario_id)
            if sessao.is_admin:
                usuario_a_desativar.is_active = True
                usuario_a_desativar.save()
                messages.success(request, 'Usuário ativado com sucesso.')
            else:
                messages.error(request, 'Você não tem permissão para ativar usuários.')
                return redirect('dashboard')
            return redirect('listar_usuarios')
        else:
            return redirect('login')
    except Usuario.DoesNotExist:
        messages.error(request, 'Usuário não encontrado.')
        return redirect('listar_usuarios')


def excluir_usuario(request, usuario_id):
    try:
        sessao_id = request.session.get('usuario_id')
        sessao = Usuario.objects.get(id=sessao_id)
        if sessao:
            usuario_a_desativar = get_object_or_404(Usuario, id=usuario_id)
            if sessao.is_admin:
                usuario_a_desativar.delete()
                messages.success(request, 'Usuário excluido com sucesso.')
            else:
                messages.error(request, 'Você não tem permissão para excluir usuários.')
                return redirect('dashboard')
            return redirect('listar_usuarios')
        else:
            return redirect('login')
    except Usuario.DoesNotExist:
        messages.error(request, 'Usuário não encontrado.')
        return redirect('listar_usuarios')


# view para USUÁRIOS ==============================//================================

def resend_activation_email(request, usuario_id):
    usuario = Usuario.objects.get(id=usuario_id)
    if usuario:
        if not usuario.is_active:
            send_activation_email(request, usuario)
            messages.success(request, 'O email de ativação foi reenviado')
        else:
            messages.info(request, 'Este usuario já está ativo')
    return redirect('dashboard')


def send_activation_email(request, usuario):
    token = generate_token(usuario.pk)
    current_site = get_current_site(request)
    mail_subject = 'Ative sua conta'
    from_email = 'sistema.jogos.senac@gmail.com'
    recipient_list = [usuario.email]
    message = render_to_string('usuarios/ativacao_email.html', {
        'user': usuario,
        'domain': current_site.domain,
        'uid': urlsafe_base64_encode(force_bytes(usuario.id)),
        'token': token,
    })
    send_mail(mail_subject, '', from_email, recipient_list, fail_silently=False, html_message=message)
    usuario.token = token
    usuario.save()


def registrar_usuario(request):
    if request.method == 'POST':
        form = UsuarioForm(request.POST)
        if form.is_valid():
            usuario = form.save(commit=False)
            usuario.password = hashlib.sha256(usuario.password.encode('utf-8')).hexdigest()
            usuario.save()
            send_activation_email(request, usuario)
            messages.success(request, 'Verifique seu email para ativar sua conta')
            return redirect('login')
        else:
            return render(request, 'usuarios/registrar_usuario.html', {'form': form})
    else:
        form = UsuarioForm()
    return render(request, 'usuarios/registrar_usuario.html', {'form': form})


def activate(request, uidb64, token):
    try:
        usuario_id = force_str(urlsafe_base64_decode(uidb64))
        usuario = Usuario.objects.defer('password').get(pk=usuario_id)
    except (TypeError, ValueError, OverflowError, Usuario.DoesNotExist):
        usuario = None

    if usuario is not None and token == usuario.token:
        usuario.is_active = True
        usuario.save()
        messages.success(request, 'Sua conta foi ativada com sucesso!')
        return redirect('login')
    else:
        messages.error(request, 'O link de ativação inválido.')
        return redirect('registrar_usuario')


def login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

            try:
                usuario = Usuario.objects.only('id', 'is_active').get(email=email, password=hashed_password)
                if usuario is not None:
                    if usuario.is_active:
                        request.session['usuario_id'] = usuario.id
                        return redirect('dashboard')
                    else:
                        form.add_error(None, 'Este usuário está desativado.')
            except Usuario.DoesNotExist:
                form.add_error(None, 'Email ou senha incorretos.')
    else:
        form = LoginForm()
    return render(request, 'usuarios/login.html', {'form': form})


def dashboard(request):
    usuario_id = request.session.get('usuario_id')
    if usuario_id:
        query = request.GET.get('q')
        usuario = Usuario.objects.defer('password').get(id=usuario_id)
        if usuario.is_admin:
            total_usuarios = Usuario.objects.filter(is_admin=False).count()
            usuarios_ativos = Usuario.objects.filter(is_admin=False, is_active=True).count()
            usuarios_inativos = total_usuarios - usuarios_ativos
            ultimos_usuarios = Usuario.objects.filter(is_admin=False).order_by('-criado_em')[:3]

            '''context = {
                'usuario': usuario,
                'total_usuarios': total_usuarios,
                'usuarios_ativos': usuarios_ativos,
                'usuarios_inativos': usuarios_inativos,
                'ultimos_usuarios': ultimos_usuarios
            }'''
            return render(request, 'produtos/dashboard.html', {'usuario': usuario,
                                                               'total_usuarios': total_usuarios,
                                                               'usuarios_ativos': usuarios_ativos,
                                                               'usuarios_inativos': usuarios_inativos,
                                                               'ultimos_usuarios': ultimos_usuarios})

        else:
            quantidade = request.GET.get('quantidade')
            produtos = Produto.objects.filter(usuario=usuario)
            if query:
                produtos = produtos.filter(
                    Q(nome__icontains=query) |
                    Q(descricao__icontains=query) |
                    Q(preco__icontains=query)
                )

            if quantidade:
                produtos = produtos.filter(Q(quantidade=quantidade))

            '''context = {
                'usuario': usuario,
                'produtos': produtos
            }'''
            return render(request, 'produtos/dashboard.html', {'usuario': usuario, 'produtos': produtos})
    else:
        return redirect('login')


def adicionar_produto(request):
    usuario_id = request.session.get('usuario_id')
    if usuario_id:
        if request.method == 'POST':
            form = ProdutoForm(request.POST, request.FILES)
            if form.is_valid():
                produto = form.save(commit=False)
                produto.usuario_id = request.session.get('usuario_id')

                if 'imagem' in request.FILES:
                    imagem = Image.open(request.FILES['imagem'])
                    buffer = io.BytesIO()
                    imagem.save(buffer, format="PNG")
                    produto.imagem = base64.b64encode(buffer.getvalue()).decode('utf-8')
                    imagem = imagem.resize((300, 300), Image.LANCZOS)
                    buffer = io.BytesIO()
                    imagem.save(buffer, format="PNG")
                    produto.thumbnail = base64.b64encode(buffer.getvalue()).decode('utf-8')

                produto.save()
                messages.success(request, f'produto \'{produto.nome}\' adicionado com sucesso!')
                return redirect('dashboard')
            else:
                return render(request, 'produtos/adicionar_produto.html', {'form': form})
        else:
            form = ProdutoForm()
        return render(request, 'produtos/adicionar_produto.html', {'form': form})
    else:
        return redirect('login')


def editar_produto(request, produto_id):
    usuario_id = request.session.get('usuario_id')
    if usuario_id:
        produto = get_object_or_404(Produto, id=produto_id, usuario_id=usuario_id)
        if request.method == 'POST':
            form = ProdutoForm(request.POST, request.FILES, instance=produto)
            if form.is_valid():
                produto = form.save(commit=False)
                produto.usuario_id = request.session.get('usuario_id')

                if 'imagem' in request.FILES:
                    imagem = Image.open(request.FILES['imagem'])
                    buffer = io.BytesIO()
                    imagem.save(buffer, format="PNG")
                    produto.imagem = base64.b64encode(buffer.getvalue()).decode('utf-8')
                    imagem = imagem.resize((300, 300), Image.LANCZOS)
                    buffer = io.BytesIO()
                    imagem.save(buffer, format="PNG")
                    produto.thumbnail = base64.b64encode(buffer.getvalue()).decode('utf-8')

                produto.save()

            form.save()

            messages.success(request, f'Produto \'{produto.nome}\' atualizado com sucesso!')
            return redirect('dashboard')

        form = ProdutoForm(instance=produto)
        return render(request, 'produtos/editar_produto.html', {'form': form, 'produto': produto})
    else:
        return redirect('login')


def excluir_produto(request, produto_id):
    usuario_id = request.session.get('usuario_id')
    if usuario_id:
        produto = get_object_or_404(Produto, id=produto_id, usuario_id=usuario_id)
        if request.method == 'POST':
            produto.delete()
            messages.success(request, f'Produto removido com sucesso!')
            return redirect('dashboard')
        return render(request, 'produtos/remover_produto.html', {'produto': produto})
    else:
        return redirect('login')


def mudar_senha(request):
    usuario_id = request.session.get('usuario_id')
    if usuario_id:
        usuario = Usuario.objects.only('email').get(id=usuario_id)
        if request.method == 'POST':
            form = MudarSenhaForm(request.POST)
            try:
                if form.is_valid():
                    old_password = form.cleaned_data['old_password']
                    new_password = form.cleaned_data['new_password']
                    confirm_password = form.cleaned_data['confirm_password']
                    hashed_old_password = hashlib.sha256(old_password.encode('utf-8')).hexdigest()
                    hashed_new_password = hashlib.sha256(new_password.encode('utf-8')).hexdigest()

                    if usuario.password == hashed_old_password:
                        if new_password == confirm_password:
                            usuario.password = hashed_new_password
                            usuario.save()
                            messages.success(request, 'Senha alterada com sucesso!')
                            return redirect('dashboard')
                        else:
                            form.add_error(None, 'As senhas não coincidem.')
                    else:
                        form.add_error(None, 'Senha atual incorreta.')
            except form.ValidationError:
                form.add_error(None, 'Corrija os erros.')
        else:
            form = MudarSenhaForm()
        return render(request, 'usuarios/mudar_senha.html', {'form': form})
    else:
        return redirect('login')


def logout(request):
    request.session.flush()
    return redirect('login')
