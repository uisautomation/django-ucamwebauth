import logging
from django.contrib.auth.models import User
from ucamwebauth import RavenResponse
from ucamwebauth.exceptions import UserNotAuthorised
from ucamwebauth.utils import setting

logger = logging.getLogger(__name__)

class RavenAuthBackend(object):
    """An authentication backend for django that uses Raven.  To use, add
    'ucamwebauth.backends.RavenAuthBackend' to AUTHENTICATION_BACKENDS
    in your django settings.py."""

    def authenticate(self, response_str=None):
        """Checks a response from the Raven server and sees if it is valid.  If
        it is, returns the User with the same username as the Raven username.
        @return User object, or None if authentication failed"""

        # Check that everything is correct, and return
        try:
            response = RavenResponse(response_str)
        except Exception as e:
            logger.error("%s: %s" % (type(e).__name__, e))
            raise e

        if not response.validate():
            return None

        if (setting('UCAMWEBAUTH_NOT_CURRENT', default=False) is False) and ('current' not in response.ptags):
            raise UserNotAuthorised()

        username = response.principal
 
        if username is None:
            return None

        return self.get_user_by_name(username)

    def get_user_by_name(self, username):
        """Gets a user with the specified username from the DB."""
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            logger.debug("Successfully authenticated as %s in Raven, but that user does not exist in Django" % username)

            if setting('UCAMWEBAUTH_CREATE_USER', default=False) is True:
                logger.debug("Creating user for %s" % username)
                return User.objects.create_user(username=username)
            else:
                logger.debug("User %s not created" % username)

            return None
        else:
            logger.debug("%s successfully authenticated via Raven" % username)
            return user

    def get_user(self, user_id):
        """Gets the user with the specified user ID. It is required by all django auth backend implementations."""
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            logger.debug("No such user: %s" % user_id)
            return None
        else:
            return user
