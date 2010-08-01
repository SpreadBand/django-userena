from django.test import TestCase
from django.core.management import call_command

from userena.models import Account
from userena import settings as userena_settings

import datetime

class CleanExpiredTests(TestCase):
    user_info = {'username': 'alice',
                 'password': 'swordfish',
                 'email': 'alice@example.com'}

    def test_clean_expired(self):
        """
        Test if ``clean_expired`` deletes all users which ``activation_key``
        is expired.

        """
        # Create an account which is expired.
        account = Account.objects.create_inactive_user(**self.user_info).account
        account.activation_key_created -= datetime.timedelta(days=userena_settings.USERENA_ACTIVATION_DAYS + 1)
        account.save()

        # There should be one account now
        Account.objects.get(user__username=self.user_info['username'])

        # Clean it.
        call_command('clean_expired')

        self.failUnlessEqual(Account.objects.filter(user__username=self.user_info['username']).count(), 0)