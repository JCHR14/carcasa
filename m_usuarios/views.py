# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import os 
from django.shortcuts import render, redirect
from django.http import *
#from django.urls import reverse
#from django.contrib.sites.shortcuts import get_current_site
#from django.db import connection
#from django.utils.encoding import force_bytes, force_text
#from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.db import transaction
from django.contrib.auth import authenticate, login as auth_login, logout
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User, Group, Permission
from django.db.models import Count, Sum 
from django.contrib import messages
from django.contrib.auth.forms import PasswordChangeForm

from config.settings import EN_SERVIDOR
from m_generales.models import *
from m_usuarios.forms import *

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
@permission_required('usuario.puede_crear_usuarios')
@transaction.atomic
def crear_usuario(request):
	if request.POST:
		form = SignUpForm(request.POST)
		if form.is_valid():
			try:
				user = form.save()
				user.refresh_from_db()  # load the profile instance created by the signal
				user.is_active = True
				#user.email = user.username
				#user.profile.auth_phone = request.POST['auth_phone']
				#user.profile.auth_email_confirmed = True
				#user.profile.auth_revise_sol_ventas = request.POST['auth_revise_sol_ventas']
				user.save()
				for x in request.POST.getlist('grupos'):
					g = Group.objects.get(id=x)
					g.user_set.add(user)
				messages.success(request, 'Usuario creado con éxito')
			except expression as identifier:
				messages.error(
					request, 'Ocurrió un problema al crear usuario, por favor revise los datos ingresados')
				grupos = Group.objects.all()
				ctx = {
					'grupos': grupos,
					'form': form
				}
				return render(request, 'usuarios_crear.html', ctx)
		else:
			messages.error(
				request, 'Ocurrió un problema al crear usuario, por favor revise los datos ingresados')
			grupos = Group.objects.all()
			ctx = {
				'form': form,
				'grupos': grupos
			}
			return render(request, 'usuarios_crear.html', ctx)
		return redirect('usuarios_listado')
	form = SignUpForm()
	grupos = Group.objects.all()
	ctx = {
		'grupos': grupos,
		'form': form
	}
	return render(request, 'crear_usuario.html', ctx)

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

