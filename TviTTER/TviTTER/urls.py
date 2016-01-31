from django.conf.urls import include, url
from django.contrib import admin

urlpatterns = [
    url(r'^$', 'TviTTER.views.home', name='home'),
    url(r'^authenticate_user/', 'TviTTER.views.authenticate_user', name='authenticate_user'),
    url(r'^upload_video/', 'TviTTER.views.media_upload',name='upload_video'),
    url(r'^signup$', 'TviTTER.views.signup',name='signup'),
    url(r'^accounts/login/$', 'TviTTER.views.user_login', name='login'),
    url(r'^accounts/logout$', 'TviTTER.views.user_logout', name='logout'),
]
