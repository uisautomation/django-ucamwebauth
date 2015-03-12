import time
try:
    from urlparse import parse_qs
    from urllib import unquote
except ImportError:
    from urllib.parse import parse_qs, unquote
from OpenSSL.crypto import FILETYPE_PEM, load_certificate, verify
from django.conf import settings
from ucamwebauth.utils import decode_sig, setting, parse_time, get_return_url
from ucamwebauth.exceptions import (MalformedResponseError, InvalidResponseError, PublicKeyNotFoundError,
                                    UserNotAuthorised, OtherStatusCode)


class RavenResponse(object):
    """Transforms a WLS-Response (http://raven.cam.ac.uk/project/waa2wls-protocol.txt) from the
    University of Cambridge web login service (WLS) a.k.a. Raven (http://raven.cam.ac.uk/) into an object with
    accessible variables corresponding to the response parameters"""

    ver = status = msg = issue = ident = url = principal = ptags = auth = sso = life = params = kid = sig = None

    STATUS = {200: 'Successful authentication',
              410: 'The user cancelled the authentication request',
              510: 'No mutually acceptable authentication types available',
              520: 'Unsupported protocol version',
              530: 'General request parameter error',
              540: 'Interaction would be required',
              560: 'WAA not authorised',
              570: 'Authentication declined'}

    def __init__(self, response_req=None):
        """Creates a RavenResponse object from the response of the Web login service (WLS) of the University of
        Cambridge
        @param response_req The HTTP request that contains the WLS response.
        """

        if response_req is None:
            raise MalformedResponseError("no request supplied")
        try:
            response_str = response_req.GET['WLS-Response']
        except KeyError:
            raise MalformedResponseError("no WLS-Response")

        # The WLS sends an authentication response message as follows:  First a 'encoded response string' is formed by
        # concatenating the values of the response fields below, in the order shown, using '!' as a separator character.
        # If the characters '!'  or '%' appear in any
        # field value they MUST be replaced by their %-encoded representation
        # before concatenation.
        # Parameters with no relevant value MUST be encoded as the empty string.
        rawtokens = response_str.split('!')
        tokens = list(map(unquote, rawtokens))  # return a list for python3 compatibility

        # ver: The version of the WLS protocol in use. May be the same as the 'ver' parameter
        # supplied in the request
        try:
            self.ver = int(tokens[0])
        except ValueError:
            raise MalformedResponseError("Version number must be an integer, not %s" % tokens[0])
        if not 4 > self.ver > 0:
            raise MalformedResponseError("Unsupported version: %d" % self.ver)

        if self.ver == 3:
            versioni = 0
        else:
            versioni = 1

        # Check that the number of parameters in the response is correct
        if len(tokens) != (14-versioni):
            raise MalformedResponseError("Wrong number of parameters in response: expected %d, got %d" %
                                         ((14-versioni), len(tokens)))

        # status: A three digit status code indicating the status of the authentication request. The list of possible
        # statuses can be seen in the STATUS dict of the RavenResponse object.
        try:
            self.status = int(tokens[1])
        except ValueError:
            raise MalformedResponseError("Status code must be an integer, not %s" % tokens[1])

        if self.status not in self.STATUS:
            raise InvalidResponseError("Status returned not known")

        # msg (optional): A text message further describing the status of the authentication request,
        # suitable for display to end-user.
        self.msg = tokens[2]

        # issue: The date and time that the authentication response was created.
        try:
            self.issue = parse_time(tokens[3])
        except ValueError:
            raise MalformedResponseError("Issue time is not a valid time, got %s" % tokens[3])

        # Check that the response is recent by comparing 'issue' with the current time. The WLS MUST and the WAA SHOULD
        # have their clocks synchronised by NTP or a similar mechanism. Providing the WAA has access to an
        # NTP-synchronised clock then allowing for a transmission time of 30-60 seconds is probably appropriate.
        # Otherwise allowance must be made for the maximum expected clock skew.
        if self.issue > time.time():
            raise InvalidResponseError("The timestamp on the response is in the future")
        if self.issue < time.time() - setting('UCAMWEBAUTH_TIMEOUT', 30):
            raise InvalidResponseError("Response has timed out - issued %s, now %s" %
                                       (time.asctime(time.gmtime(self.issue)), time.asctime()))

        # ident: An identifier for this response. 'ident', combined with 'issue' provides a uid for this response.
        self.ident = tokens[4]

        if self.ident == "":
            raise MalformedResponseError("Empty ID")

        # url: The value of url supplied in the authentication request and used to form the authentication response.
        self.url = tokens[5]

        # Check that 'url' represents the resource currently being
        # accessed.  The request has already been checked against
        # ALLOWED_HOSTS by Django.
        if self.url != get_return_url(response_req):
            raise InvalidResponseError("The URL in the response does not match the URL expected")

        # principal: Only present if status == 200, indicates the authenticated identity of the user
        if self.status == 200:
            if tokens[6] != "":
                self.principal = tokens[6]
            else:
                raise InvalidResponseError("The username is not present in the WLS response")
        else:
            if tokens[6] != "":
                raise InvalidResponseError("The username should not be present if the status code is not 200")

        # ptags (optional): A potentially empty sequence of text tokens separated by ',' indicating attributes
        # or properties of the identified principal. Possible values of this tag are not standardised and are
        # a matter for local definition by individual WLS operators (see note below). Web application agent (WAA)
        # SHOULD ignore values that they do not recognise.
        if versioni == 0:
            self.ptags = tokens[7].split(',')

        # auth (not-empty only if authentication was successfully established by interaction with the user):
        # This indicates which authentication type was used. v3 only supports 'pwd'
        self.auth = tokens[8-versioni]

        # sso (not-empty only if 'auth' is empty): Authentication must have been established based on previous
        # successful authentication interaction(s) with the user. This indicates which authentication types were used
        # on these occasions. This value consists of a sequence of text tokens as described below, separated by ','.
        self.sso = tokens[9-versioni].split(',')

        # life (optional): If the user has established an authenticated 'session' with the WLS, this indicates the
        # remaining life (in seconds) of that session. If present, a WAA SHOULD use this to establish an upper limit
        # to the lifetime of any session that it establishes.
        # TODO https://docs.djangoproject.com/en/dev/topics/http/sessions/#django.contrib.sessions.backends.base.SessionBase.set_expiry
        if tokens[10-versioni] != "":
            try:
                self.life = int(tokens[10-versioni])
            except ValueError:
                raise MalformedResponseError("Life parameter must be an integer, not %s" % tokens[10-versioni])

        # params: a copy of the params parameter from the request
        try:
            self.params = parse_qs(tokens[11-versioni])
        except Exception:
            raise MalformedResponseError("The params field contains wrong characters: %s" % tokens[11-versioni])

        # REQUIRED to be a copy of the params parameter from the request
        # if self.params != setting('UCAMWEBAUTH_PARAMS', default=''):
        #     raise InvalidResponseError("The params are not equals to the request ones")

        # kid (not-empty only if 'sig' is present): A string which identifies the RSA key which was used to form the
        # signature supplied with the response. Typically these will be small integers.
        if tokens[12-versioni] != "":
            try:
                self.kid = int(tokens[12-versioni])
            except ValueError:
                raise MalformedResponseError("kid parameter must be an integer, not %s" % tokens[12-versioni])

        # sig (not-empty only if 'status' is 200): A public-key signature of the response data constructed from the
        # entire parameter value except 'kid' and 'sig' (and their separating ':' characters) using the private key
        # identified by 'kid', the SHA-1 hash algorithm and the 'RSASSA-PKCS1-v1_5' scheme as specified in PKCS #1 v2.1
        # [RFC 3447] and the resulting signature encoded using the base64 scheme [RFC 1521] except that the
        # characters '+', '/', and '=' are replaced by '-', '.' and '_' to reduce the URL-encoding overhead.
        if tokens[13-versioni] != "":
            if self.kid is None:
                raise InvalidResponseError("kid must be present if signature is present")
            self.sig = decode_sig(tokens[13-versioni])
        else:
            if self.status == 200:
                raise InvalidResponseError("Signature must be present if status is 200")

        # Check that 'kid', corresponds to a key/certificate present in the WAA. Is the only way to check the
        # signature. The WAA has to use the public key/certificate made available by the WLS.
        if (self.sig is not None) or (self.status == 200):
            try:
                cert = load_certificate(FILETYPE_PEM, settings.UCAMWEBAUTH_CERTS[self.kid])
            except Exception:
                raise PublicKeyNotFoundError("The server do not have the public key corresponding to the key the web "
                                             "login service signed the response with")

            # Check that the signature matches the data supplied. To check this, the WAA uses the public key identified
            # by 'kid'.
            data = '!'.join(rawtokens[0:(12-versioni)])
            # The data string that was signed in the WLS (everything from the  WLS-Response except 'kid' and 'sig'
            try:
                verify(cert, self.sig, data.encode(), 'sha1')
            except Exception:
                raise InvalidResponseError("The signature for this response is not valid.")

        if self.status == 200:

            # Check that 'auth' and/or 'sso' contain values acceptable to the WAA. Simply setting 'aauth' and 'iact'
            # values in an authentication request is not sufficient since an attacker could construct its own request.
            # Conversely, the WAA MUST ensure that the values of 'aauth' and/or 'iact' in its authentication requests
            # correctly reflect its requirement, to prevent the WLS sending it unacceptable responses.

            UCAMWEBAUTH_IACT = setting('UCAMWEBAUTH_IACT', '')

            # the authentication was successfully establish by interaction with the user
            if self.auth != "":
                # auth only supports 'pwd' in current version, therefore we compare it with 'pwd' only
                # If more are supported in the future, a setting will be added to specify which ones the WAA wants to
                # support and check that auth and sso match any element in this list.
                if self.auth != "pwd":
                    raise InvalidResponseError("The response used the wrong type of authentication (auth)")

                if UCAMWEBAUTH_IACT == 'no':
                    # We had required a non-interactive authentication, but didn't get one
                    raise InvalidResponseError("Non-interactive authentication required but not received")

            # authentication was established on a previous interaction(s) with the user
            else:
                if self.sso != [""]:
                    if self.sso != ["pwd"]:
                        raise InvalidResponseError("The response used the wrong type of authentication (sso)")

                    if UCAMWEBAUTH_IACT == 'yes':
                        # We had required an interactive authentication, but didn't get one
                        raise InvalidResponseError("Interactive authentication required but not received")
                else:
                    # Both auth and sso are empty, which is not allowed
                    raise MalformedResponseError("No authentication types supplied")

    def validate(self):
        """Returns True if this represents a successful authentication otherwise returns False."""
        return self.status == 200
