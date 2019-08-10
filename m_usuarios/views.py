# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.shortcuts import render, redirect
from django.http import *
#from django.urls import reverse
from django.contrib.auth import authenticate, login as auth_login, logout
from django.contrib.auth.decorators import login_required, permission_required
from django.db import transaction
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User, Group, Permission
from m_generales.models import *
from m_usuarios.forms import *
import os 
from django.conf import settings
from django.db.models import Count, Sum 
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.db import connection
import ldap
from tickets.settings import EN_SERVIDOR
from django.contrib.humanize.templatetags.humanize import *
from tickets.tokens import account_activation_token, account_reset_token
from tickets.send_email import email_activacion, email_contacto, email_resetPwd
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

@login_required()
@permission_required('usuarios.listar_usuarios')
def listado_usuarios(request):
	listado_usuarios = User.objects.values('id', 'username', 'first_name', 
		'last_name', 'email', 'is_active').all()
	ctx = {
		'listado_usuarios':listado_usuarios,
	}
	return render(request, 'listado_usuarios.html', ctx )


@login_required()
@permission_required('auth.crear_usuario')
@transaction.atomic
def crear_usuario(request): 
	if request.POST:
		import random
		import string
		with transaction.atomic():
			try:
				if not User.objects.filter(username=request.POST['email']).exists():
					us = User()
					us.username = request.POST['email']
					us.first_name = request.POST['first_name']
					us.last_name = request.POST['last_name']
					us.email = request.POST['email']
					us.set_password('Temporal123')
					us.is_active = False
					us.save()
					for x in request.POST.getlist('grupos'):
						g = Group.objects.get(id=x)
						g.user_set.add(us)
					toRange = 15
					x1 = ''.join(random.choice(string.ascii_uppercase + string.digits)for _ in range(toRange))
					x2 = ''.join(random.choice(string.ascii_uppercase + string.digits)for _ in range(toRange))
					codigo_con = str(x1)+''+str(us.pk)+''+str(x2)

					current_site = get_current_site(request)
					subject = 'BI NETWORK OPERATION CENTER: Mensaje de bienvenida'
					message = render_to_string('correos/mensaje_bienvenida.html', {
						'user': us,
						'domain': current_site.domain,
						'uid': codigo_con,
						'token': account_reset_token.make_token(us),
					})
					email_resetPwd(us.email, subject, message)
					messages.success(request, 'Usuario creardo con éxito')
				else:
					messages.error(request, 'Usuario ya existe')
			except Exception as e:
				print (e)
				messages.error(request, 'Ocurrió un problema al crear usuario')
		return redirect('listado_usuarios')
	
	grupos = Group.objects.all()
	ctx ={
		'grupos':grupos,
	}
	return render(request, 'crear_usuario.html', ctx )

def activate(request, uidb64, token):
	if request.POST:
		try:
			uid = uidb64[15:][:-15]
			user = User.objects.get(pk=uid)
			form = AdminPasswordChangeForm(user, request.POST)
		except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
			messages.error(request, 'No se pudo realizar activación de cuenta')
			return redirect('login')
			
		if form.is_valid():
			form.save()
			user.is_active = True
			user.save()
			messages.success(request, 'Activación de cuenta realizada con éxito')

		else:
			messages.error(request, 'No se pudo realizar activación de cuenta')
			ctx = {
				'form': form,
				'user': user,
			}
			return render(request, 'activate.html', ctx)

		#return redirect(reverse('usuarios_detalle', kwargs={'id': id}))
		return redirect('login')

	else:
		try:
			uid = uidb64[15:][:-15]
			user = User.objects.get(pk=uid)
		except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
			user = None
		if user is not None and user.is_active == True:
			messages.info(request, 'Cuenta ya ha sido activada anteriormente')
			return redirect('login')

		if user is not None and account_activation_token.check_token(user, token):
			try:
				user = User.objects.get(pk=uid)
				form = AdminPasswordChangeForm(user)
			except Exception as e:
				messages.error(request, 'Ocurrió un problema al obtener usuario')
				return redirect('login')
			ctx = {
				'form': form, 'user': user,
			}
			return render(request, 'activate.html', ctx)
		else:
			return redirect('login')


@login_required()
@permission_required('auth.editar_usuario')
@transaction.atomic
def editar_usuario(request, codigo):
	if request.POST:
		with transaction.atomic():
			try:
				us = User.objects.get(pk = request.POST['user_id'])
				us.first_name = request.POST['first_name']
				us.last_name = request.POST['last_name']
				#us.set_password('Temporal123')
				us.is_active = request.POST['is_active']
				us.save()
				us.groups.clear()

				for x in request.POST.getlist('grupos'):
					g = Group.objects.get(id=x)
					g.user_set.add(us)
				messages.success(request, 'Usuario editado con éxito')
			except Exception as e:
				print (e)
				messages.error(request, 'Ocurrió un problema al editar usuario')
		return redirect('listado_usuarios')
	else:
		try:
			usr = User.objects.get(pk = codigo)
		except Exception as e:
			print (e)
		grupos = Group.objects.all()

		ctx ={
			'grupos':grupos,
			'usr':usr,
		}
		return render(request, 'editar_usuario.html', ctx )


@login_required()
@transaction.atomic
def change_password(request):
	if request.method == 'POST':
		form = PasswordChangeForm(request.user, request.POST)
		if form.is_valid():
			user = form.save()
			update_session_auth_hash(request, user)
			messages.success(request, 'Contraseña actualizada correctamente')
			return redirect('inicio')
		else:
			messages.error(request, 'No se pudo actualizar contraseña')

			return render(request, 'change_password.html', {'form': form})
	else:
		form = PasswordChangeForm(request.user)
	return render(request, 'change_password.html', {'form': form})

@login_required()
@permission_required('auth.ver_grupo_list')
@transaction.atomic
def listado_grupos(request):
	listado_grupos = Group.objects.all()
	ctx = {
		'listado_grupos': listado_grupos,
	}
	return render(request, 'listado_grupos.html', ctx )

@login_required()
@permission_required('auth.crear_grupo')
@transaction.atomic
def crear_grupo(request):
	if request.POST:
		with transaction.atomic():
			try:
				gp = Group()
				gp.name = request.POST['name'][:80]
				gp.save()

				for x in request.POST.getlist('permisos'):
					per = Permission.objects.get(id = x)
					gp.permissions.add(per)

				messages.success(request, 'Grupo creado con éxito')
			except Exception as e:
				print (e)
				messages.error(request, 'Ocurrió un problema al crear grupo')
		return redirect('listado_grupos')
	else:
		listado_permisos = Permission.objects.all().order_by('-content_type')

		ctx = {
			'listado_permisos':listado_permisos,
		}
		return render(request, 'crear_grupo.html', ctx )

@login_required()
@permission_required('auth.editar_grupo')
@transaction.atomic
def editar_grupo(request, codigo):
	if request.POST:
		with transaction.atomic():
			try:
				gp = Group.objects.get(pk = request.POST['id'])
				gp.name = request.POST['name'][:80]
				gp.save()
				gp.permissions.clear()
				for x in request.POST.getlist('permisos'):
					per = Permission.objects.get(id = x)
					gp.permissions.add(per)
				messages.success(request, 'Grupo editado con éxito')
			except Exception as e:
				print (e)
				messages.error(request, 'Ocurrió un problema al editar grupo')
		return redirect('listado_grupos')
	else:
		gp = Group.objects.get(pk = codigo)
		listado_permisos = Permission.objects.all().order_by('-content_type')
		ctx = {
			'listado_permisos':listado_permisos,
			'gp':gp
		}
		return render(request, 'editar_grupo.html', ctx )

