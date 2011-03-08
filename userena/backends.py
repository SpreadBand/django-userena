from django.core.validators import email_re
from django.contrib.auth.backends import ModelBackend

from django.contrib.auth.models import User

class UserenaAuthenticationBackend(ModelBackend):
    """
    Custom backend because the user must be able to supply a ``email`` or
    ``username`` to the login form.

    The backends also allows to steal the identity of a user when you
    are a superuser.
    """
    def authenticate(self, identification, password=None, check_password=True):
        """
        Authenticates a user through the combination email/username with
        password.

        :param identification:
            A string containing the username or e-mail of the user that is
            trying to authenticate.

        :password:
            Optional string containing the password for the user.

        :param check_password:
            Boolean that defines if the password should be checked for this
            user.  Always keep this ``True``. This is only used by userena at
            activation when a user opens a page with a secret hash.

        :return: The signed in :class:`User`.

        """
        user = self._lookup_identification(identification)

        if user and check_password:
            # Standard "username/pass" challenge
            if user.check_password(password):
                return user
            # If we are a superuser, we can steal the identity of
            # someone else by using the following login:
            # username: 'username'
            # password: 'superuser_username/superuser_password'
            #
            # e.g. username: 'johndoe', password: 'admin/adminpass'
            elif '/' in password:
                requested_user = user # Who we want to be
                (superuser_identification, superuser_password) = password.split('/', 1)
                superuser = self._lookup_identification(superuser_identification)
                if superuser and superuser.is_superuser:
                    if superuser.check_password(superuser_password):
                        return requested_user
            else:
                return None
        else: 
            return user

    def _lookup_identification(self, identification):
        """
        Given an identification (either a username or en email),
        return the user object.
        """
        if email_re.search(identification):
            # Looks like an email. Since emails are not case sensitive
            # and many users have a habit of typing them in mixed
            # cases, we will normalize them to lower case. This assumes
            # that the database has done the same thing.
            try: user = User.objects.get(email__iexact=identification)
            except User.DoesNotExist: return None
        else:
            try: user = User.objects.get(username__iexact=identification)
            except User.DoesNotExist: return None

        return user

    def get_user(self, user_id):
        """
        Given a user id, return the user object
        """
        try: return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
