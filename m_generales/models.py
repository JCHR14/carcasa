from __future__ import unicode_literals
from django.db import models
from django.contrib.auth.models import User

class CrmProductos(models.Model):
    prod_id = models.AutoField(primary_key=True)
    prod_nombre = models.CharField(max_length=50, blank=True, null=True)
    prod_responsable = models.CharField(max_length=50, blank=True, null=True)
    prod_email = models.CharField(max_length=254, blank=True, null=True)
    prod_estado = models.NullBooleanField()
    class Meta:
        managed = False
        db_table = 'crm_productos'

class ExtracrmAgencias(models.Model):
    agencia_id = models.AutoField(primary_key=True)
    agencia_nombre = models.CharField(max_length=50, blank=True, null=True)
    agencia_estado = models.NullBooleanField()
    user_creador = models.ForeignKey(User, models.DO_NOTHING, db_column='user_creador', blank=True, null=True)
    fecha_creacion = models.DateTimeField(blank=True, null=True, auto_now_add=True)
    user_modificador = models.ForeignKey(User, models.DO_NOTHING, db_column='user_modificador', blank=True, null=True, related_name='agencia_modificador')
    fecha_modificacion = models.DateTimeField(blank=True, null=True, auto_now=True)
    class Meta:
        managed = False
        db_table = 'extracrm_agencias'


class ExtracrmUserAgencia(models.Model):
    user_agencia_id = models.AutoField(primary_key=True)
    agencia = models.ForeignKey(ExtracrmAgencias, models.DO_NOTHING, blank=True, null=True)
    user = models.ForeignKey(User, models.DO_NOTHING, blank=True, null=True)
    class Meta:
        managed = False
        db_table = 'extracrm_user_agencia'



