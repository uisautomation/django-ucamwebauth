#   Copyright 2011 Andrew Ryrie (amr66)

"""Classes to let django applications interact easily with pyroven.
@package pyroven.pyroven_django
@file pyroven/pyroven_django.py"""

import urllib
import traceback

from django.contrib.auth.models import User
from django.http import HttpResponseRedirect

from pyroven import (MalformedResponseError, InvalidResponseError, RavenConfig,
                     PublicKeyNotFoundError, RavenResponse)

class HttpResponseSeeOther(HttpResponseRedirect):
    """An HttpResponse with a 303 status code, since django doesn't provide one
    by default.  A 303 is required by the the WAA2WLS specification."""
    status_code = 303

class Raven(object):
    """A singleton to keep track of any settings associated with the
    authentication system, such as server, public key, etc."""

    # Errors associated with Raven
    class NotInitialisedError(Exception):
        """Raised if a required value has not been initialised."""
        pass

    config = None

    _instance = None
    def __new__(cls):
        """Override __new__ to make this a singleton"""
        if cls._instance == None:
            cls._instance = super(Raven, cls).__new__(cls)
        return cls._instance

    def redirect_raven():
        """Returns a django HttpResponse redirecting to the raven login page.
        @exception NotInitialisedError if the login URL has not been set"""
        login_url = config.get_login_url()
        if login_url is None:
            raise NotInitialisedError("The login URL has not been initialised")
        return HttpResponseSeeOther(login_url)

    def authenticate(self, response_str):
        """Checks a response to see if the user has successfully authenticated.
        @param request  A django HttpRequest
        @exception MalformedResponseError if there was a problem with the
        server's response
        @return str instance or None; if None, the user has failed the
        authentication; if a str, the user's CRSid"""

        # This can raise a MalformedResponseError, but if it does it's just
        # passed on
        response = RavenResponse(response_str, self.config)

        # Check that everything is correct, and return
        if not response.validate():
            return None
        else:
            return response.principal

    def get_login_redirect(self):
        """Returns a django HttpResponse redirecting the user to the raven login
        page."""
        encoded_return_url = urllib.quote(self.config.return_url)
        return HttpResponseSeeOther("%s?ver=%d&url=%s" % (self.config.login_url,
                                                          self.config.ver,
                                                          encoded_return_url)
                                    )


class RavenAuthBackend(object):
    """An authentication backend for django that uses Raven.  To use, add
    'pyroven.pyroven_django.RavenAuthBackend' to AUTHENTICATION_BACKENDS in your
    django settings.py."""

    def authenticate(self, response_str=None):
        """Checks a response from the Raven server and sees if it is valid.  If
        it is, returns the User with the same username as the Raven username.
        @return User object, or None if authentication failed"""

        raven = Raven()

        if response_str is None:
            return None

        try:
            username = raven.authenticate(response_str)
        except MalformedResponseError:
            print("Got a malformed response from the Raven server")
            # If the response was malformed, we're not allowed to login
            return None
        except InvalidResponseError:
            print("Got an invalid reponse from the Raven server")
            return None
        except PublicKeyNotFoundError:
            print("Cannot find a public key for the server's response")
            return None
        except Exception as e:
            traceback.print_exc()
            return None
        
        if username is None:
            return None

        user = self.get_user_by_name(username)
        return user

    def get_user_by_name(self, username):
        """Gets a user with the specified username from the DB."""
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            print("Successfully authenticated as %s in Raven, but that user "
                  "does not exist in Django" % username)
            return None
        else:
            print("%s successfully authenticated via Raven" % username)
            return user

    def get_user(self, user_id):
        """Gets a user with the specified user ID from the DB.  For some
        reason, this is required by django for an auth backend."""
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            print("No such user: %s" % user_id)
            return None
        else:
            return user
