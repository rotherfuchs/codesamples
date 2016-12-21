import datetime
import sys

from spyne.application import Application
from spyne.protocol.soap import Soap11
from spyne.server.django import DjangoApplication
from spyne.decorator import rpc
from spyne.service import ServiceBase
from spyne.model.complex import Iterable
from spyne.util.django import DjangoComplexModel
from spyne.model.primitive import Integer, Unicode, Date, DateTime, UnsignedInteger16, UnsignedInteger
from spyne.error import ArgumentError, ResourceNotFoundError

from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from django.conf import settings

from models import AuditTrail, UserProfile, send_audit_trail
from decorators import has_perm_or_basicauth

from devicementor import tools
from devicementor.soap import StatusComplexType

APP_LABEL = 'usermanager'

class AuditTrailComplexType(DjangoComplexModel):
    class Attributes(DjangoComplexModel.Attributes):
        django_model = AuditTrail


class AuditTrailReadonlyService(ServiceBase):

    @rpc(Unicode, _returns=UnsignedInteger)
    def getAuditTrailCountByUsername(self, username):
        """ Returns Number of Existing Audit Trails for Given Username """

        if not username:
            raise ArgumentError(unicode(_(u'Please provide a valid username!')))

        return AuditTrail.objects.filter(user__username=username).count()

    @rpc(_returns=Iterable(AuditTrailComplexType))
    def getRecentAuditTrails(self):
        """ Returns Audit Trails of Last 24 Hours """

        date_range = timezone.localtime(timezone.now()) - datetime.timedelta(hours=24)
        return AuditTrail.objects.filter(date__gte=date_range)

    @rpc(Integer, _returns=Iterable(AuditTrailComplexType))
    def getRecentAuditTrailsByLogLevel(self, level):
        """ Returns Audit Trails of Last 24 Hours for Given Level """

        if not level:
            raise ArgumentError(unicode(_(u'Please provide a valid level!')))

        date_range = timezone.localtime(timezone.now()) - datetime.timedelta(hours=24)
        return AuditTrail.objects.filter(level=AuditTrail.LEVEL_CRITICAL).filter(date__gte=date_range).filter(level=level)

    @rpc(Unicode, _returns=Iterable(AuditTrailComplexType))
    def getRecentAuditTrailsByUsername(self, username):
        """ Returns Audit Trails of Last 24 Hours for a User """

        if not username:
            raise ArgumentError(unicode(_(u'Please provide a valid username!')))

        date_range = timezone.localtime(timezone.now()) - datetime.timedelta(hours=24)
        return AuditTrail.objects.filter(user__username=username).filter(date__gte=date_range).order_by('-date')

    @rpc(DateTime, _returns=Iterable(AuditTrailComplexType))
    def getAuditTrailsSince(self, date):
        """ Returns Recent Audit Trails Since Given Date

        @param date <datetime>: The given date

        """

        if not date:
            raise ArgumentError(unicode(_(u'Please provide a valid DateTime, i.e. 2014-01-01T12:15:00!')))

        return AuditTrail.objects.filter(date__gte=date).order_by('-date')[:settings.SOAP_MAX_ENTRIES]

    @rpc(Date, _returns=Iterable(AuditTrailComplexType))
    def getAuditTrailsByDate(self, date):
        """ Returns Recent Audit Trails On Given Date And Tolerance.

        @param date <datetime>: The given date
        """

        if not date:
            raise ArgumentError(unicode(_(u'Please provide a valid Date, i.e. 2014-01-01!')))

        date_min = datetime.datetime.combine(date, datetime.time.min)
        date_max = datetime.datetime.combine(date, datetime.time.max)
        return AuditTrail.objects.filter(date__gte=date_min).filter(date__lte=date_max).order_by('-date')[:settings.SOAP_MAX_ENTRIES]


class UserComplexType(DjangoComplexModel):
    class Attributes(DjangoComplexModel.Attributes):
        django_model = User


class UserProfileComplexType(DjangoComplexModel):
    class Attributes(DjangoComplexModel.Attributes):
        django_model = UserProfile


class UserReadOnlyService(ServiceBase):

    @rpc(Integer, _returns=UserComplexType)
    def getUserByID(self, id):
        """ Returns Recent Audit Trails On Given Date And Tolerance.

        @param date <datetime>: The given date
        """

        try:
            return User.objects.get(id=id)
        except User.DoesNotExist:
            raise

    @rpc(Integer, _returns=UserProfileComplexType)
    def getUserProfileByID(self, id):
        """ Returns Recent Audit Trails On Given Date And Tolerance.

        @param date <datetime>: The given date
        """

        try:
            return UserProfile.objects.get(user__id=id)
        except UserProfile.DoesNotExist:
            return None

    @rpc(Unicode, _returns=UserProfileComplexType)
    def getUserProfileByUsername(self, username):
        """ Returns Recent Audit Trails On Given Date And Tolerance.

        @param date <datetime>: The given date
        """

        try:
            return UserProfile.objects.get(user__username=username)
        except UserProfile.DoesNotExist:
            return None


class InputUserComplexType(DjangoComplexModel):
    class Attributes(DjangoComplexModel.Attributes):
        django_model = User
        django_exclude = ('id', 'last_login', 'date_joined')


class InputUserProfileComplexType(DjangoComplexModel):
    class Attributes(DjangoComplexModel.Attributes):
        django_model = UserProfile
        django_exclude = ('user_id', 'id')


class UserReadWriteService(ServiceBase):

    @rpc(Unicode, Unicode, _returns=StatusComplexType)
    def changePassword(self, username, password):
        """ Change a user's password.
        The user will have to change his password upon next login and will
        also be informed via email.

        @param username <str>: The username
        @param password <str>: The new password

        """

        response = StatusComplexType()

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise ResourceNotFoundError(username)

        user.set_password(password)
        user.save()
        user.userprofile.force_password_change = True
        user.userprofile.save()

        response.status_code = 200
        response.message = unicode(_(u"New password set for user ``%(username)s``. User was notified about it." % {'username': username}))

        message = _("""Hi, %(first_name)s,
your password has been changed through an administrator.
Your temporary password is:
    \n%(password)s\n
Please log into the system and assign a new pasword of your choice.""" % ({'first_name': user.first_name, 'password': password}))

        user.email_user(_('Your Password Was Changed!'), unicode(message))

    @rpc(Unicode, _returns=StatusComplexType)
    def suspendUser(self, username):
        """ Suspend a user - can be activated again with ``activateUser``

        @param username <str>: The username

        """

        response = StatusComplexType()

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise ResourceNotFoundError(username)

        user.is_active = False
        user.save()

        response.status_code = 200
        response.message = unicode(_(u"User suspended."))
        return response

    @rpc(Unicode, _returns=StatusComplexType)
    def activateUser(self, username):
        """ Activate a suspended user.

        @param username <str>: The username

        """

        response = StatusComplexType()

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise ResourceNotFoundError(username)

        user.is_active = True
        user.save()

        response.status_code = 200
        response.message = unicode(_(u"User ``%(username)s`` activated" % {'username': username}))
        return response

    @rpc(InputUserComplexType, _returns=StatusComplexType)
    def addUser(self, new_user):
        """ Add a new User """

        response = StatusComplexType()

        user, created = User.objects.get_or_create(username=new_user.username)
        if not created:
            raise ResourceNotFoundError(new_user)
        user.__dict__.update(new_user.__dict__)
        user.save()

        response.status_code = 200
        response.message = unicode(_(u"User ``%(username)s`` successfully added!" % {'username': new_user.username}))
        return response


@has_perm_or_basicauth(prefix=APP_LABEL)
def audittrail_readonly_service_view(request):
    AuditTrail.audit_trail_soap_event(request)
    audittrail_readonly_service = DjangoApplication(Application([AuditTrailReadonlyService], tns='devicementor', in_protocol=Soap11(validator='lxml'), out_protocol=Soap11()))
    return audittrail_readonly_service(request)
audittrail_readonly_service_view = csrf_exempt(audittrail_readonly_service_view)
tools.update_soap_group_permissions(settings.SOAP_READONLY_GROUP, AuditTrailReadonlyService, APP_LABEL)

@has_perm_or_basicauth(prefix=APP_LABEL)
def user_readonly_service_view(request):
    AuditTrail.audit_trail_soap_event(request)
    user_readonly_service = DjangoApplication(Application([UserReadOnlyService], tns='devicementor', in_protocol=Soap11(validator='lxml'), out_protocol=Soap11()))
    return user_readonly_service(request)
user_readonly_service_view = csrf_exempt(user_readonly_service_view)
tools.update_soap_group_permissions(settings.SOAP_READONLY_GROUP, UserReadOnlyService, APP_LABEL)

@has_perm_or_basicauth(prefix=APP_LABEL)
def user_readwrite_service_view(request):
    AuditTrail.audit_trail_soap_event(request)
    user_readwrite_service = DjangoApplication(Application([UserReadWriteService], tns='devicementor', in_protocol=Soap11(validator='lxml'), out_protocol=Soap11()))
    return user_readwrite_service(request)
user_readwrite_service_view = csrf_exempt(user_readwrite_service_view)
tools.update_soap_group_permissions(settings.SOAP_READWRITE_GROUP, UserReadWriteService, APP_LABEL)
