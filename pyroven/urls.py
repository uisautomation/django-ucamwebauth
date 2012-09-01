from django.conf.urls import patterns, include, url

from pyroven.views import login, logout, raven_return

urlpatterns = patterns('',

    url(r'^login/$', pyroven_login, name='pyroven_login'),
    url(r'^logout/$', pyroven_logout, name='pyroven_logout'),
    url(r'^raven-return/$', pyroven_return, name='pyroven_return'),

)
