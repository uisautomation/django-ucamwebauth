"""Base configuration for Raven login """
import time
import urllib

from OpenSSL.crypto import FILETYPE_PEM, load_certificate, verify

from ucamwebauth.utils import decode_sig, setting, parse_time
from ucamwebauth.exceptions import (MalformedResponseError, InvalidResponseError, PublicKeyNotFoundError,
                                    UserNotAuthorised)


class RavenResponse(object):
    """Represents a response from the raven server.  Contains fields for
    version number, status, etc. and methods for checking the validity of the
    response via the RSA signature."""

    ver = status = msg = issue = ident = url = principal = ptags = auth = sso = life = params = kid = sig = config = \
        None

    STATUS = {200: 'Successful authentication',
              410: 'User cancelled authentication',
              510: 'No mutually acceptable authentication types available',
              520: 'Unsupported protocol version',
              530: 'General request parameter error',
              540: 'Interaction would be required',
              560: 'WAA not authorised to use this WLS',
              570: 'Authentication declined'}

    def __init__(self, response_str=None):
        """Makes a Ravenresponse object from a reponse string passed with HTTP GET.
        @param reponse_str The response string, normally passed as GET['WLS-Response']
        """

        if response_str is None:
            raise MalformedResponseError("Version number must be integer")

        UCAMWEBAUTH_RETURN_URL = setting('UCAMWEBAUTH_RETURN_URL')
        UCAMWEBAUTH_MAX_CLOCK_SKEW = setting('UCAMWEBAUTH_MAX_CLOCK_SKEW', 2)
        UCAMWEBAUTH_TIMEOUT = setting('UCAMWEBAUTH_TIMEOUT', 10)
        UCAMWEBAUTH_AAUTH = setting('UCAMWEBAUTH_AAUTH', ['pwd', 'card'])
        UCAMWEBAUTH_IACT = setting('UCAMWEBAUTH_IACT', False)
        UCAMWEBAUTH_CERTS = setting('UCAMWEBAUTH_CERTS')

        # The response is a !-separated list of variables, so split it by !
        tokens = response_str.split('!')

        # Check we have the right version
        try:
            self.ver = int(tokens[0])
        except ValueError:
            raise MalformedResponseError("Version number must be integer")

        if self.ver != 3:
            raise MalformedResponseError("Unsupported version: %d" % self.ver)

        if len(tokens) != 14:
            raise MalformedResponseError("Wrong number of parameters in response: expected 14, got %d" % len(tokens))
        
        # Get all the tokens from the request
        try:
            self.status = int(tokens[1])
        except ValueError:
            raise MalformedResponseError("Status code must be an integer, not %s" % tokens[1])
        self.msg = tokens[2]
        try:
            self.issue = parse_time(tokens[3])
        except ValueError:
            raise MalformedResponseError("Issue time is not a valid Raven time, not %s" % tokens[3])
        self.ident = tokens[4]
        self.url = urllib.unquote(tokens[5])
        self.principal = tokens[6]
        self.ptags = tokens[7].split(',')
        self.auth = tokens[8]
        self.sso = tokens[9]
        if tokens[10] == "":
            self.life = None
        else:
            try:
                self.life = int(tokens[10])
            except ValueError:
                raise MalformedResponseError("Life must be an integer, not %s" % tokens[10])
        self.params = tokens[11]
        self.kid = tokens[12]
        self.sig = decode_sig(tokens[13])
        
        # Check that the URL is as expected
        if self.url != UCAMWEBAUTH_RETURN_URL:
            raise InvalidResponseError("The URL in the response does not match the URL expected")

        # Check that the issue time is not in the future or too far in the past:
        if self.issue > time.time() + UCAMWEBAUTH_MAX_CLOCK_SKEW:
            raise InvalidResponseError("The timestamp on the response is in the future")
        if self.issue < time.time() - UCAMWEBAUTH_MAX_CLOCK_SKEW - UCAMWEBAUTH_TIMEOUT:
            raise InvalidResponseError("Response has timed out - issued %s, now %s" %
                                       (time.asctime(time.gmtime(self.issue)), time.asctime()))

        # Check that the type of authentication was acceptable
        if self.auth != "":
            # Authentication was done recently with this auth type
            if UCAMWEBAUTH_AAUTH is not None:
                # if UCAMWEBAUTH_AAUTH == None, any type of authentication is acceptable
                if self.auth not in UCAMWEBAUTH_AAUTH:
                    raise InvalidResponseError("The response used the wrong type of authentication")
        elif self.sso != "" and not UCAMWEBAUTH_IACT:
            # Authentication was not done recently, and that is acceptable to us
            if UCAMWEBAUTH_IACT is not None:
                
                # Get the list of auth types used on previous occasions and
                # check that at least one of them is acceptable to us
                auth_good = False
                for auth_type in self.sso.split(','):
                    if auth_type in UCAMWEBAUTH_AAUTH:
                        auth_good = True
                        break

                # If none of the previous types match one we asked for, raise an error
                if not auth_good:
                    raise InvalidResponseError("The response used the wrong type of authentication")
        else:
            if UCAMWEBAUTH_IACT:
                # We had required an interactive authentication, but didn't get one
                raise InvalidResponseError("Interactive authentication required but not received")
            else:
                # Both auth and sso are empty, which is not allowed
                raise MalformedResponseError("No authentication types supplied")
        # Done checking the authentication type was acceptable

        # Check that the signature is correct - first get the certificate
        try:
            cert = load_certificate(FILETYPE_PEM, UCAMWEBAUTH_CERTS[self.kid])
        except KeyError:
            raise PublicKeyNotFoundError("We do not have the public key "
                                         "corresponding to the key the server "
                                         "signed the response with")

        # Create data string used for hash http://raven.cam.ac.uk/project/waa2wls-protocol-3.0.txt
        data = '!'.join(tokens[0:12])
        
        # Check that it matches
        try:
            verify(cert, self.sig, data.encode(), 'sha1')
        except Exception:
            raise InvalidResponseError("The signature for this response is not valid.")

    def validate(self):
        """Returns True if this represents a successful authentication otherwise returns False."""
        return self.status == 200