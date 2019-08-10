# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.shortcuts import render, redirect
from django.http import *
from django.contrib.auth import authenticate, login as auth_login, logout
from django.contrib.auth.decorators import login_required, permission_required
from django.db import transaction
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User, Group, Permission
from m_generales.models import *
import os
from django.conf import settings
from django.db.models import Count, Sum 
from django.contrib import messages
from django.template import RequestContext
from django.db import connection
from tickets.settings import EN_SERVIDOR
from django.contrib.humanize.templatetags.humanize import *


## AADTokenCredentials for multi-factor authentication
from msrestazure.azure_active_directory import AADTokenCredentials

## Required for Azure Data Lake Analytics job management
from azure.mgmt.datalake.analytics.job import DataLakeAnalyticsJobManagementClient
from azure.mgmt.datalake.analytics.job.models import JobInformation, JobState, USqlJobProperties

## Other required imports
import adal
import uuid
import time

def dictfetchall(cursor):
	columns = [col[0] for col in cursor.description]
	return [
		dict(zip(columns, row))
		for row in cursor.fetchall()
	]

def floatcomma(value):
	#orig = force_unicode(value)
	intpart, dec = value.split(".")
	intpart = intcomma(intpart) 
	return ".".join([intpart, dec]) 


def salir(request):
	logout(request)
	return redirect('inicio')


def authenticate_username_password(user, contra):
	try:
		"""
		Authenticate using user w/ username + password.
		This doesn't work for users or tenants that have multi-factor authentication required.
		"""
		authority_host_uri = 'https://login.microsoftonline.com'
		#authority_host_uri = 'https://login.microsoftonline.com/common/oauth2/nativeclient'

		tenant = 'bi-dss.com'  # '<TENANT>'
		authority_uri = authority_host_uri + '/' + tenant
		resource_uri = 'https://management.core.windows.net/'
		username = str(user) #'<USERNAME>'
		password = str(contra) #'<PASSWORD>'
		client_id = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'

		#client_id = '449117d2-0432-425b-ad11-7d35444aa5c2'  # '<CLIENT_ID>'

		context = adal.AuthenticationContext(authority_uri, api_version=None)
		mgmt_token = context.acquire_token_with_username_password(
			resource_uri, username, password, client_id)
		credentials = AADTokenCredentials(mgmt_token, client_id)
		print (credentials)
		return credentials
	except Exception as e:
		print (e)
		return False
 

def login(request):
	ctx = {}
	if request.user.id:
		return redirect('inicio')
	if request.POST:
		username = request.POST['username']
		password = request.POST['password']
		resultado = authenticate_username_password(username, password)
		if resultado != False:
			try:
				if User.objects.filter(username=username).exists():
					usr = User.objects.get(username = username)
					usr.set_password(password)
					usr.save()
				else:
					data = getNameFromEmail(username)
					nombre = data[0]
					apellido = data[1]
					us = User()
					us.username = username
					us.first_name = nombre.capitalize()
					us.last_name = apellido.capitalize()
					us.email = username
					us.set_password(password)
					us.is_active = True
					us.save()
			except Exception as e:
				print (e)
				return redirect('login')
			user = authenticate(username=username, password=password)
			if user is not None:
				if user.is_active:
					auth_login(request, user)
					return redirect('inicio')
			else:
				ctx = {
					'error': True,
					'username': username,
				}
				return render(request, 'login.html', ctx)
		else:
			user = authenticate(username=username, password=password)
			if user is not None:
				if user.is_active:
					auth_login(request, user)
					return redirect('inicio')

		ctx = {
			'error': True,
			'username': username,
		}
	return render(request, 'login.html', ctx)

@login_required()
def inicio(request):
	#x = Permission.objects.all().order_by('content_type')
	ctx = {
	}
	return render(request, 'inicio.html', ctx)

def handler404(request, *args, **argv):
	return render(request, '404.html', {})

def handler500(request, *args, **argv):
	return render(request, '500.html', {})



def getNameFromEmail(email):
	data = email.split('@')
	data = data[0]
	data = data.split('.')
	return data
	
