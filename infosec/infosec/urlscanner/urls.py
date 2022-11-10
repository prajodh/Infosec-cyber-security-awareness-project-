from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

app_name='urlscanner'

urlpatterns=[
    path("urlscanner/",views.urlscanner,name='urlscanner'),
    path("ipaddress/",views.ipaddress_scanner,name='ipaddress'),
    path("clickjacking/",views.clickjacking,name='clickjacking'),
    path('filescanner/',views.filescanner,name='filescanner'),
    path('image_encrypt/',views.image_encrypt,name='image_encrypt')

]+static(settings.MEDIA_URL,document_root=settings.MEDIA_ROOT)