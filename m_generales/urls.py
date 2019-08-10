from django.conf.urls import url
from m_generales import views
from django.conf import settings
from django.conf.urls.static import static
 
urlpatterns = [
    url(r'^$', views.login, name='login'),
    url(r'^salir/$', views.salir, name='salir'),
    url(r'^inicio/$', views.inicio, name='inicio'),

]