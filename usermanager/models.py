#!/usr/bin/env python

"""Describes Models for this App.

UserProfile describes a configuration set for one user account.
create_user_profile() is called whenever a new user was added
(i.e. through the Admin Panel) and ensures the link between the
internal Django user and the enhanced UserProfile.

"""
import syslog

from django.db import models
from django.db.models.signals import pre_save, post_save, post_delete
from django.conf import settings
from django.dispatch import receiver
from django.contrib.auth.models import User  # , Permission
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
# from django.test.signals import setting_changed


class UserProfile(models.Model):
    """User Account"""

    enabled = models.BooleanField(default=False)
    user = models.OneToOneField(User, help_text=_(u'userid'))
    force_password_change = models.BooleanField(default=False, help_text=_(u'If True, User has to change password on next login'))
    # user = models.ForeignKey(settings.AUTH_USER_MODEL, help_text=_(u'userid'))

    def __unicode__(self):
        return self.user.username


@receiver(pre_save, sender=User, dispatch_uid='UserProfilePasswordChange')
def password_change_signal(sender, instance, **kwargs):
    """ Password was changed. If force_password_flag was set, unset it """
    try:
        user = User.objects.get(username=instance.username)
        if not user.password == instance.password:
            profile = user.userprofile
            profile.force_password_change = False
            profile.save()
    except User.DoesNotExist:
        pass


class AuditTrail(models.Model):
    LEVEL_DEBUG = 0
    LEVEL_INFO = 1
    LEVEL_WARNING = 2
    LEVEL_ERROR = 3
    LEVEL_CHOICES = (
        (LEVEL_DEBUG, _(u'Debug')),
        (LEVEL_INFO, _(u'Info')),
        (LEVEL_WARNING, _(u'Warning')),
        (LEVEL_ERROR, _(u'Error')),
    )

    user = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)
    # user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)
    # do not set `auto_now` as this will let tests fail. `auto_now` would drop any custom passed date.
    date = models.DateTimeField(default=timezone.now, help_text=_(u'Event Occurrence'))
    message = models.CharField(default='', blank=True, max_length=250, help_text=_(u'Event Description'))
    level = models.PositiveSmallIntegerField(default=LEVEL_DEBUG, choices=LEVEL_CHOICES, help_text=_(u'Event Type'))

    @classmethod
    def audit_trail_soap_event(cls, request, level=LEVEL_INFO):
        """ Takes a HTTP SOAP Request and creates Audit Trail from it """

        soap_action = request.environ.get('HTTP_SOAPACTION')
        if soap_action is None:
            if 'wsdl' in request.GET.keys():
                soap_action = '( Fetching WSDL )'
            else:
                soap_action = 'Unknown ??'

        send_audit_trail(
            request.user,
            _(u'Call to SOAP Interface %(method_name)s at %(path)s') % ({'method_name': soap_action, 'path': request.environ['PATH_INFO']}),
            level
        )


@receiver(post_save, sender=User, dispatch_uid="UserProfileLink")
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

    else:
        # Check if only last_update was updated if so, it's
        # probably a user login. Skip that.
        update_fields = kwargs.get('update_fields', None)
        if update_fields and 'last_login' in update_fields:
            if len(update_fields) == 1:
                return

        # nothing created and nothing updated -> nothing happened!
        if update_fields is None:
            return
        message = _(u'Updated user: `%s`: %s' % (instance.username, update_fields))

        send_syslog(syslog.LOG_NOTICE, message)
        send_audit_trail(instance, message, AuditTrail.LEVEL_INFO)


def send_syslog(level, message):
    """ Sends a message to SYSLOG """
    level = 1

    # message comes as gettext object
    if hasattr(message, '_proxy____cast'):
        message = unicode(message)

    syslog.openlog(settings.SYSLOG_NAME)
    syslog.syslog(level, message)
    syslog.closelog()


def send_audit_trail(user, message, level):
    """ Logs an Audit Trail Event """
    if level >= settings.AUDIT_TRAIL_LOG_LEVEL:

        # message = u'[%s] %s' % (unicode(AuditTrail.LEVEL_CHOICES[level][1]), message)
        event = AuditTrail(user=user, message=message, level=level)
        event.save()


@receiver(user_logged_in)
def trail_login_event(sender, request, user, **kwargs):
    message = _(u'User %s logged in' % user)
    send_syslog(syslog.LOG_INFO, message)
    send_audit_trail(user, message, AuditTrail.LEVEL_INFO)


@receiver(user_logged_out)
def trail_logout_event(sender, request, user, **kwargs):
    message = _(u'User %s logged out' % user)
    send_syslog(syslog.LOG_INFO, message)
    send_audit_trail(user, message, AuditTrail.LEVEL_INFO)


@receiver(user_login_failed)
def trail_login_failed_event(sender, credentials, **kwargs):
    user = User.objects.filter(username=credentials.get('username'))
    if user:
        message = _(u'User failed login attempt (wrong password)')
        send_syslog(syslog.LOG_INFO, message)
        send_audit_trail(user[0], message, AuditTrail.LEVEL_INFO)


@receiver(post_save, sender=UserProfile)
def trail_user_add_modify(sender, instance, created, **kwargs):
    update_fields = kwargs.get('update_fields', None)

    # creation only possible as result of User object creation.
    # no need to do anything here as already signaled by that.
    if created:
        message = _(u'Created User: `%s`' % (instance.user.username))
    else:
        # nothing created and nothing updated -> nothing happened!
        if update_fields is None:
            return
        message = _(u'Updated user profile: `%s`: %s' % (instance.user.username, update_fields))

    send_syslog(syslog.LOG_NOTICE, message)
    send_audit_trail(instance.user, message, AuditTrail.LEVEL_INFO)


@receiver(post_delete, sender=User)
def trail_userprofile_remove(sender, instance, **kwargs):
    message = _(u'Removed User: `%s`' % instance.username)
    send_syslog(syslog.LOG_NOTICE, message)
    send_audit_trail(instance, message, AuditTrail.LEVEL_WARNING)
