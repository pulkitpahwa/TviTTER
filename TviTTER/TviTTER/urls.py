from django.conf.urls import include, url
from django.contrib import admin

urlpatterns = [
    # Examples:
    url(r'^$', 'TviTTER.views.home', name='home'),
    url(r'^blog/', 'TviTTER.views.blog'),
    url(r'^oauth_finder/', 'TviTTER.views.find_oauth_verifier'),

    url(r'^admin/', include(admin.site.urls)),
]
