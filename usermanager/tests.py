import string
import random
import suds
from datetime import timedelta, datetime

from django.test import TestCase
from django.contrib.auth.models import User, Group
from django.utils import timezone
from django.conf import settings
from django.core.urlresolvers import reverse
from spyne.error import ArgumentError, ResourceNotFoundError

from devicementor import tools
from devicementor.tests import SOAPTestCase

from models import AuditTrail, UserProfile
from soap import AuditTrailReadonlyService, UserReadOnlyService, UserReadWriteService

APP_LABEL = 'usermanager'


class AuditTrailReadonlyServiceTestCase(TestCase):

    """ Audit Trail Logic Test Case """

    @classmethod
    def setUpClass(cls):
        cls.username = 'temporaryuser'
        cls.password = 'temporarypassword'

        super(AuditTrailReadonlyServiceTestCase, cls).setUpClass()

    def setUp(self):
        self.assertEqual(
            settings.AUDIT_TRAIL_LOG_LEVEL, AuditTrail.LEVEL_DEBUG)
        self.user = User.objects.create_user(
            self.username, 'temporary@gmail.com', self.password)

    def test_user_modification_raises_audit_trail(self):
        """ User Creation / Modification Flow """
        self.assertTrue(AuditTrail.objects.count() >= 1)
        self.assertEqual(
            AuditTrail.objects.last().level, AuditTrail.LEVEL_INFO)

    def test_user_login(self):
        """ User Login Event Shall Create Audit Trail """
        self.client.login(username=self.username, password=self.password)
        self.assertTrue(AuditTrail.objects.count() >= 2)
        self.assertEqual(
            AuditTrail.objects.last().level, AuditTrail.LEVEL_INFO)

    def test_user_login_does_not_audit_save(self):
        """ User Login does not create a `save` event """
        self.user.save(update_fields=['last_login'])
        self.assertTrue(AuditTrail.objects.count() >= 1)
        self.assertEqual(
            AuditTrail.objects.last().level, AuditTrail.LEVEL_INFO)

    def test_user_modification(self):
        """ Modifying a User Object Shall Create Audit Trail """
        self.user.save(update_fields=['first_name'])
        self.assertTrue(AuditTrail.objects.count() >= 2)
        self.assertEqual(
            AuditTrail.objects.last().level, AuditTrail.LEVEL_INFO)

    def test_userprofile_modification(self):
        """ Modifying a UserProfile Object Shall Create Audit Trail """
        self.user.userprofile.save(update_fields=['enabled'])
        self.assertTrue(AuditTrail.objects.count() >= 2)
        self.assertEqual(
            AuditTrail.objects.last().level, AuditTrail.LEVEL_INFO)

    def test_user_logout(self):
        """ User Logout Creates Audit Trail """
        self.client.logout()
        self.assertTrue(AuditTrail.objects.count() >= 2)
        self.assertEqual(
            AuditTrail.objects.last().level, AuditTrail.LEVEL_INFO)

    def test_user_deletion(self):
        """ User Deletion Creates Audit Trail """
        User.objects.filter(username=self.user.username).delete()
        self.assertTrue(AuditTrail.objects.count() >= 2)
        self.assertEqual(
            AuditTrail.objects.last().level, AuditTrail.LEVEL_WARNING)

    def test_login_failure(self):
        """ Login Failure Creates Audit Trail """
        self.client.login(username=self.username, password='AWrongPassword')
        # 2: creation and login
        self.assertTrue(AuditTrail.objects.count() >= 2)
        self.assertEqual(
            AuditTrail.objects.last().level, AuditTrail.LEVEL_INFO)


class SOAPAuditTrailReadOnlyTestCase(SOAPTestCase):

    """ Audit Trail Permission Test Case """

    def setUp(self):
        super(SOAPAuditTrailReadOnlyTestCase, self).setUp()

        self.wsdl = self.host + \
            reverse('usermanager:soap.audittrail_readonly') + '?wsdl'
        # Database is cleared after each test!
        # Update Permissions - ensure group exists
        tools.update_soap_group_permissions(
            settings.SOAP_READONLY_GROUP, AuditTrailReadonlyService, APP_LABEL)

        self.group = Group.objects.get(name=settings.SOAP_READONLY_GROUP)
        self.group.user_set.add(self.user)

    def createAuditTrail(self, date=False):
        if not date:
            date = timezone.localtime(timezone.now())

        message = ''.join(
            random.choice(string.ascii_letters) for _ in range(100))
        event = AuditTrail(
            user=self.user, message=message, level=AuditTrail.LEVEL_DEBUG, date=date)
        event.save()
        return event

    def test_wsdl_requires_auth(self):
        self._test_wsdl_requires_auth()

    def test_wsdl_accepts_auth(self):
        self._test_wsdl_accepts_auth()

    def test_permission_denied_no_permission(self):
        """ Tests that user cannot access interfaces without permissions """

        # Remove user from group ( added in setUpClass ) -> no permission
        self.group.user_set.remove(self.user)

        c = suds.client.Client(
            self.wsdl, username=self.username, password=self.password)
        result_code, result_msg = c.service.getRecentAuditTrails()
        self.assertEqual(result_code, 401)

    def test_permission_denied_wrong_creds(self):
        """ Tests that user cannot access interfaces with wrong credentials """

        # run client with wrong password
        c = suds.client.Client(
            self.wsdl, username=self.username, password='AWrongPassword')
        result_code, result_msg = c.service.getRecentAuditTrails()
        self.assertEqual(result_code, 401)

    def test_getAuditTrailCountByUsername(self):
        """ Verify AuditTrail Count """

        event = AuditTrail(
            user=self.user, message='temporarymsg', level=AuditTrail.LEVEL_DEBUG)
        event.save()

        c = suds.client.Client(
            self.wsdl, username=self.username, password=self.password)
        result = c.service.getAuditTrailCountByUsername(self.username)
        expected = AuditTrail.objects.filter(
            user__username=self.username).count()

        self.assertEqual(result, expected)

    def test_getRecentAuditTrails(self):
        """ Testing getRecentAuditTrails """

        c = suds.client.Client(
            self.wsdl, username=self.username, password=self.password)
        result = c.service.getRecentAuditTrails()

        date_range = timezone.localtime(timezone.now()) - timedelta(hours=24)
        expected = AuditTrail.objects.filter(date__gte=date_range).count()
        self.assertEqual(len(result.AuditTrailComplexType), expected)

        __dbitems = [
            AuditTrail.objects.get(pk=i.id) for i in result.AuditTrailComplexType]
        self.assertTrue(__dbitems[-1].level, AuditTrail.LEVEL_INFO)

        [self.assertEqual(trail.user_id, self.user.id)
         for trail in result.AuditTrailComplexType]

    def test_getRecentAuditTrailsByUsername(self):
        """ Verify Count And Username """

        c = suds.client.Client(
            self.wsdl, username=self.username, password=self.password)
        result = c.service.getRecentAuditTrailsByUsername(self.user.username)
        self.assertTrue(len(result.AuditTrailComplexType) >= 2)

        [self.assertEqual(trail.user_id, self.user.id)
         for trail in result.AuditTrailComplexType]

    def test_getAuditTrailsSince(self):
        """ Verify No Audit Trail is Older Than Given Date """

        c = suds.client.Client(
            self.wsdl, username=self.username, password=self.password)

        # create a bunch of old Audit Trails, older than 1 hour
        event1_date = timezone.localtime(
            timezone.now()) - timedelta(days=3 * 365)
        self.createAuditTrail(date=event1_date)

        event2_date = timezone.localtime(timezone.now()) - timedelta(hours=25)
        self.createAuditTrail(date=event2_date)

        event3_date = timezone.localtime(timezone.now()) - timedelta(hours=1)
        self.createAuditTrail(date=event3_date)

        # take the date and time of now
        date = timezone.localtime(timezone.localtime(timezone.now()))

        # and create an Audit Trail in the future
        event4_date = timezone.localtime(timezone.now()) + timedelta(hours=5)
        self.createAuditTrail(date=event4_date)

        # and for fun.. aonther one!
        event5_date = timezone.localtime(timezone.now()) + timedelta(days=1)
        self.createAuditTrail(date=event5_date)

        # okay we got 4 ATs in the past, and 2 in the future.
        # If we now ask for ATs not older than 1 hour in the future, we
        # should only get the ones +1hr in the future.

        # login AT is created NOW, but we're asking for the future!
        soap_result = c.service.getAuditTrailsSince(date + timedelta(hours=1))
        self.assertTrue(len(soap_result.AuditTrailComplexType) >= 2)

        # check results for correct user are returned
        [self.assertEqual(trail.user_id, self.user.id)
         for trail in soap_result.AuditTrailComplexType]
        # check ordering
        self.assertTrue(soap_result.AuditTrailComplexType[
                        0].date > soap_result.AuditTrailComplexType[1].date)

    def test_getAuditTrailsByDate(self):
        """ Verify All Audit Trails Are Returned For Given Date """

        c = suds.client.Client(
            self.wsdl, username=self.username, password=self.password)

        # create a bunch of old Audit Trails, older than 1 hour
        event1_date = timezone.localtime(
            timezone.now()) - timedelta(days=3 * 365)
        self.createAuditTrail(date=event1_date)

        event2_date = timezone.localtime(timezone.now()) - timedelta(days=25)
        self.createAuditTrail(date=event2_date)

        event3_date = timezone.localtime(timezone.now()) - timedelta(days=151)
        self.createAuditTrail(date=event3_date)

        # take the date and time of today
        date = datetime.today().date()

        # and create an Audit Trail of right now
        event4_date = date - timedelta(hours=5)
        self.createAuditTrail(date=event4_date)

        # okay we got 4 ATs in the past, and 2 in the future.
        # If we now ask for ATs not older than 1 hour in the future, we
        # should only get the ones +1hr in the future.

        # login AT is created NOW, but we're asking for the future!
        soap_result = c.service.getAuditTrailsByDate(date)
        self.assertTrue(len(soap_result.AuditTrailComplexType) >= 3)

        # check results for correct user are returned
        [self.assertEqual(trail.user_id, self.user.id)
         for trail in soap_result.AuditTrailComplexType]
        # check ordering
        self.assertEqual(soap_result.AuditTrailComplexType[
                         0].date, soap_result.AuditTrailComplexType[1].date)
        # check max entries
        self.assertTrue(
            len(soap_result.AuditTrailComplexType) <= settings.SOAP_MAX_ENTRIES)


class SOAPUserReadOnlyTestCase(SOAPTestCase):

    def setUp(self):
        super(SOAPUserReadOnlyTestCase, self).setUp()

        self.wsdl = self.host + \
            reverse('usermanager:soap.user_readonly') + '?wsdl'
        # Database is cleared after each test!
        # Update Permissions - ensure group exists
        tools.update_soap_group_permissions(
            settings.SOAP_READONLY_GROUP, UserReadOnlyService, APP_LABEL)

        self.group = Group.objects.get(name=settings.SOAP_READONLY_GROUP)
        self.group.user_set.add(self.user)

    def test_wsdl_requires_auth(self):
        self._test_wsdl_requires_auth()

    def test_wsdl_accepts_auth(self):
        self._test_wsdl_accepts_auth()

    def test_permission_denied_no_permission(self):
        """ Tests that user cannot access interfaces without permissions """

        # Remove user from group ( added in setUpClass ) -> no permission
        self.group.user_set.remove(self.user)

        c = suds.client.Client(
            self.wsdl, username=self.username, password=self.password)
        result_code, result_msg = c.service.getUserByID(1)
        self.assertEqual(result_code, 401)

    def test_permission_denied_wrong_creds(self):
        """ Tests that user cannot access interfaces with wrong credentials """

        # run client with wrong password
        c = suds.client.Client(
            self.wsdl, username=self.username, password='AWrongPassword')
        result_code, result_msg = c.service.getUserByID(1)
        self.assertEqual(result_code, 401)

    def test_getUserByID(self):
        c = suds.client.Client(
            self.wsdl, username=self.username, password=self.password)
        result = c.service.getUserByID(self.user.id)
        self.assertEqual(result.id, self.user.id)

    def test_getUserByID_with_invalid_id_raises_500(self):
        c = suds.client.Client(
            self.wsdl, username=self.username, password=self.password)
        result_code, result_msg = c.service.getUserByID(99999)
        self.assertEqual(result_code, 500)

    def test_getUserProfileByID(self):
        c = suds.client.Client(
            self.wsdl, username=self.username, password=self.password)
        c.options.cache.clear()

        result = c.service.getUserProfileByID(self.user.id)
        self.assertEqual(result.user_id, self.user.id)

    def test_getUserProfileByUsername(self):
        c = suds.client.Client(
            self.wsdl, username=self.username, password=self.password)
        result = c.service.getUserProfileByUsername(self.username)
        self.assertEqual(result.user_id, self.user.id)


class SOAPUserReadWriteTestCase(SOAPTestCase):

    def setUp(self):
        super(SOAPUserReadWriteTestCase, self).setUp()

        self.wsdl = self.host + \
            reverse('usermanager:soap.user_readwrite') + '?wsdl'
        # Database is cleared after each test!
        # Update Permissions - ensure group exists
        tools.update_soap_group_permissions(
            settings.SOAP_READWRITE_GROUP, UserReadWriteService, APP_LABEL)

        self.group = Group.objects.get(name=settings.SOAP_READWRITE_GROUP)
        self.group.user_set.add(self.user)

    def test_wsdl_requires_auth(self):
        self._test_wsdl_requires_auth()

    def test_wsdl_accepts_auth(self):
        self._test_wsdl_accepts_auth()

    def test_permission_denied_no_permission(self):
        """ Tests that user cannot access interfaces without permissions """

        # Remove user from group ( added in setUpClass ) -> no permission
        self.group.user_set.remove(self.user)

        c = suds.client.Client(
            self.wsdl, username=self.username, password=self.password)
        result_code, result_msg = c.service.changePassword(
            'temporary', 'temporary')
        self.assertEqual(result_code, 401)

    def test_permission_denied_wrong_creds(self):
        """ Tests that user cannot access interfaces with wrong credentials """

        # run client with wrong password
        c = suds.client.Client(
            self.wsdl, username=self.username, password='AWrongPassword')
        result_code, result_msg = c.service.changePassword(
            'temporary', 'temporary')
        self.assertEqual(result_code, 401)

    def test_changePassword(self):
        c = suds.client.Client(
            self.wsdl, username=self.username, password=self.password)
        result = c.service.changePassword(self.username, 'someNewPassword')

        self.assertTrue(
            UserProfile.objects.get(user__username=self.username).force_password_change)

        # after changing password, force_password_change must be set to False
        # again
        self.user.set_password('anotherNewPassword')
        self.user.save()
        self.assertFalse(
            UserProfile.objects.get(user__username=self.username).force_password_change)

    def test_changePassword_unknown_user_raises_404(self):
        c = suds.client.Client(
            self.wsdl, username=self.username, password=self.password)
        result = c.service.changePassword('NonExistingUser', 'someNewPassword')

        self.assertRaises(ResourceNotFoundError)

    def test_suspendUser(self):
        c = suds.client.Client(
            self.wsdl, username=self.username, password=self.password)
        result = c.service.suspendUser(self.username)

        self.assertRaises(ResourceNotFoundError)
        self.assertFalse(User.objects.get(username=self.username).is_active)

    def test_suspendUser_unknown_user_raises_404(self):
        c = suds.client.Client(
            self.wsdl, username=self.username, password=self.password)
        result = c.service.suspendUser('NonExistingUser')

        self.assertRaises(ResourceNotFoundError)

    def test_activateUser(self):
        c = suds.client.Client(
            self.wsdl, username=self.username, password=self.password)
        result = c.service.activateUser(self.username)

        self.assertRaises(ResourceNotFoundError)
        self.assertTrue(User.objects.get(username=self.username).is_active)

    def test_activateUser_unknown_user_raises_404(self):
        c = suds.client.Client(
            self.wsdl, username=self.username, password=self.password)
        result = c.service.activateUser('NonExistingUser')

        self.assertRaises(ResourceNotFoundError)
