from django.conf.urls import include, url
from django.contrib import admin

urlpatterns = [
    url(r'^$', 'TviTTER.views.home', name='home'),
    url(r'^authenticate_user/', 'TviTTER.views.authenticate_user'),
    url(r'^upload_video/', 'TviTTER.views.media_upload'),
    url(r'^signup$', 'TviTTER.views.signup'),
    url(r'^accounts/login/$', 'TviTTER.views.user_login', name='login'),
    url(r'^accounts/logout$', 'TviTTER.views.user_logout', name='logout'),
    url(r'^admin/', include(admin.site.urls)),
]
