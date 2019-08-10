from django.conf.urls import url
from m_usuarios import views
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
 
urlpatterns = [
   ############################# URLS PARA CLIENTES ############################
    url(r'^listado-usuarios/$', views.listado_usuarios, name='listado_usuarios'),
    url(r'^crear-usuario/$', views.crear_usuario, name='crear_usuario'),
    url(r'^editar-usuario/(?P<codigo>\d+)/$', views.editar_usuario, name='editar_usuario'),
    path('cambiar-password/', views.change_password, name='change_password'),
    url(r'^activate/(?P<uidb64>.+)/(?P<token>.+)/$',views.activate, name='activate'),
    url(r'^listado-grupos/$', views.listado_grupos, name='listado_grupos'),
    url(r'^crear-grupo/$', views.crear_grupo, name='crear_grupo'),
    url(r'^editar-grupo/(?P<codigo>\d+)/$', views.editar_grupo, name='editar_grupo'),
    

]
