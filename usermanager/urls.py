from django.conf.urls import patterns, url

from views import login_user, logout_user
from soap import audittrail_readonly_service_view, user_readonly_service_view, user_readwrite_service_view

urlpatterns = patterns(
    '',
    url(r'login/', login_user, name='login_user'),
    url(r'logout/', logout_user, name='logout_user'),
    url(r'soap/audittrail_readonly/', audittrail_readonly_service_view, name="soap.audittrail_readonly"),
    url(r'soap/user_readonly/', user_readonly_service_view, name="soap.user_readonly"),
    url(r'soap/user_readwrite/', user_readwrite_service_view, name="soap.user_readwrite"),
)
