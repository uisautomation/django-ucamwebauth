#   Copyright 2011 Andrew Ryrie (amr66)
#
#   This file is part of pyroven
#
#   pyroven is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Lesser General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.

#   pyroven is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.

#   You should have received a copy of the GNU Lesser General Public License
#   along with pyroven.  If not, see <http://www.gnu.org/licenses/>.


"""Python-based authentication for the University of Cambridge's UCam-WebAuth
service, aka Raven."""

import calendar, time
import ast
import hashlib
import urllib
from binascii import hexlify
from string import maketrans
from base64 import b64decode
from ConfigParser import RawConfigParser, NoSectionError, NoOptionError

from M2Crypto import X509

def log(msg):
    pass
#    print msg

def parse_time(t):
    """Converts a time of the form '20110729T123456Z' to a number of seconds
    since the epoch.
    @exception ValueError if the time is not a valid Raven time"""
    time_struct = time.strptime(t, "%Y%m%dT%H%M%SZ")
    return calendar.timegm(time_struct)

class MalformedResponseError(Exception):
    """Raised if a response from the raven server is malformed."""
    pass

class InvalidResponseError(Exception):
    """Raised if the response from the server is parseable but still not
    valid"""
    pass

class PublicKeyNotFoundError(Exception):
    """Raised if the server signs the response with a key which we don't have
    the public part of"""
    pass

def decode_sig(sig):
    """Decodes a signature from the variant base64 used by raven.
    @param sig  A string giving the signature in Raven's variant base-64
    @return  A binary string containing the signature"""
    table = maketrans("-._", "+/=")
    sig = str(sig).translate(table)
    try:
        return b64decode(sig)
    except TypeError:
        raise MalformedResponseError("Signature is not a valid base-64 encoded "
                                     "string")

class RavenResponse(object):
    """Represents a response from the raven server.  Contains fields for
    version number, status, etc. and methods for checking the validity of the
    response via the RSA signature."""

    """@brief the protocol version number"""
    ver = None

    """@brief the status code for the response"""
    status = None

    """@brief any message that came with the response"""
    msg = None

    """@brief the date and time the response was issued"""
    issue = None

    """@brief an identifier of this response, unique when combined with issue"""
    ident = None

    """@brief the url this response should be being returned to"""
    url = None

    """@brief the user's username / CRSid"""
    principal = None

    """@brief the way authentication was establilshed (password, card, etc.)"""
    auth = None

    """@brief the way auth was previously established, if it wasn't this time"""
    sso = None

    """@brief time left on the user's raven session"""
    life = None

    """@brief params any parameters passed to the raven login"""
    params = None

    """@brief the id number of the key used to sign the response"""
    kid = None

    """@brief the signature of the response"""
    sig = None


    """@brief the configuration used to set up the raven authentication"""
    config = None

    STATUS = {200:'Successful authentication',
              410:'User cancelled authentication',
              510:'No mutually acceptable authentication types available',
              520:'Unsupported protocol version',
              530:'General request parameter error',
              540:'Interaction would be required',
              560:'WAA not authorised to use this WLS',
              570:'Authentication declined'}

    def __init__(self, response_str, config):
        """Makes a Ravenresponse object from a reponse string passed with
        HTTP GET.
        @param reponse_str The response string, normally passed as
        GET['WLS-Response']"""
        log("RavenResponse constructor")

        self.config = config
        
        # The response is a !-separated list of variables, so split it by !
        tokens = response_str.split('!')

        # Check we have the right version
        try:
            self.ver = int(tokens[0])
        except ValueError:
            log("Version is not integer")
            raise MalformedResponseError("Version number must be integer")
            
        if self.ver != self.config.ver:
            log("Version number doesn't match config")
            raise MalformedResponseError("Version number does not match that "
                                         "in the configuration")

        if self.ver < 1 or self.ver > 2:
            log("Version number not supported")
            raise MalformedResponseError("Unsupported version: %d" % self.ver)

        if len(tokens) != 13:
            log("wrong number params in response")
            raise MalformedResponseError("Wrong number of parameters in "
                                         "response: expected 13, got %d"
                                         % len(tokens))
        
        # Get all the tokens from the request
        try:
            self.status = int(tokens[1])
        except ValueError:
            log("status code must be integer")
            raise MalformedResponseError("Status code must be an integer, not "
                                          "%s" % tokens[1])
        self.msg = tokens[2]
        try:
            self.issue = parse_time(tokens[3])
        except ValueError:
            log("Issue time is not a valid raven time")
            raise MalformedResponseError("Issue time is not a valid Raven "
                                          "time, not %s" % tokens[3])
        self.ident = tokens[4]
        self.url = urllib.unquote(tokens[5])
        self.principal = tokens[6]
        self.auth = tokens[7]
        self.sso = tokens[8]
        if tokens[9] == "":
            self.life = None
        else:
            try:
                self.life = int(tokens[9])
            except ValueError:
                log ("lifetime is not an integer")
                raise MalformedResponseError("Life must be an integer, not %s"
                                             % tokens[9])
        self.params = tokens[10]
        self.kid = tokens[11]
        self.sig = decode_sig(tokens[12])
        
        # Check that the URL is as expected
        if self.url != self.config.return_url:
            log("URL does not match")
            raise InvalidResponseError("The URL in the response does not match "
                                       "the URL expected")

        # Check that the issue time is not in the future or too far in the past:
        if self.issue > time.time() + self.config.max_clock_skew:
            log("Timestamp in future")
            raise InvalidResponseError("The timestamp on the response is in "
                                       "the future")
        if self.issue < time.time() - self.config.max_clock_skew - self.config.timeout:
            
            log("Response has timed out - issued %s, now %s" % (time.asctime(time.gmtime(self.issue)),
                                                                time.asctime()))
            raise InvalidResponseError("The response has timed out")

        # Check that the type of authentication was acceptable
        log ("Checking authentication types")
        if self.auth != "":
            # Authentication was done recently with this auth type
            if self.config.aauth != None:
                # if self.config.aauth == None, any type of authentication is
                # acceptable
                if self.auth not in self.config.aauth:
                    log("Wrong type of auth")
                    raise InvalidResponseError("The reponse used the wrong "
                                               "type of authentication")
        elif self.sso != "" and not self.config.iact:
            # Authentication was not done recently, and that is acceptable to us
            if self.config.aauth != None:
                
                # Get the list of auth types used on previous occasions and
                # check that at least one of them is acceptable to us
                auth_good = False
                for auth_type in self.sso.split(','):
                    if auth_type in self.config.aauth:
                        auth_good = True
                        break

                # If none of the previous types match one we asked for, raise an
                # error
                if not auth_good:
                    log("Wrong type of auth")
                    raise InvalidResponseError("The response used the wrong "
                                               "type of authentication")
        else:
            if self.config.iact:
                # We had required an interactive authentication, but didn't get
                # one
                log("Interactive authentication required")
                raise InvalidResponseError("Interactive authentication "
                                           "required but not received")
            else:
                # Both auth and sso are empty, which is not allowed
                log("no authentication types supplied")
                raise MalformedResponseError("No authentication types supplied")
        # Done checking the authentication type was acceptable

        # Check that the signature is correct - first get the certificate
        log("Checking signature")
        try:
            cert = self.config.pubkeys[self.kid]
        except KeyError:
            log("unknown public key")
            raise PublicKeyNotFoundError("We do not have the public key "
                                         "corresponding to the key the server "
                                         "signed the response with")

        # Get the public key
        key = cert.get_pubkey()
        key = key.get_rsa()
        log(key)

        # Find the SHA-1 hash of the main part of the response
        data = '!'.join(tokens[0:11])
        sha1 = hashlib.sha1()
        sha1.update(data)
        hashed = sha1.digest()
        log(hexlify(hashed))
        log(data)
        
        # Check that it matches
        ret = key.verify(hashed, self.sig)
        if ret != 1:
            log("invalid signature")
            raise InvalidResponseError("The signature for this response is not "
                                       "valid")

    def validate(self):
        """Returns True if this represents a successful authentication;
        otherwise returns False."""
        return self.status == 200


class RavenConfig(object):
    """Represents a raven configuration."""

    """@brief the login url of the raven server"""
    login_url = "https://raven.cam.ac.uk/auth/authenticate.html"

    """@brief the logout url of the raven server"""
    logout_url = "https://raven.cam.ac.uk/auth/logout.html"

    """@brief the url on this server to return to from raven"""
    return_url = None

    """@brief the version of the protocol to use"""
    ver = 2

    """@brief the maximum difference between the local and remote clocks to
    tolerate, in seconds, including network delay"""
    max_clock_skew = 2

    """@brief the time before an issued response expires, in seconds"""
    timeout = 10

    """@brief a list of acceptable authentication methods to use (pwd, card)"""
    aauth = ['pwd', 'card']

    """@brief whether the authentication is required to be interactive"""
    iact = False

    """@brief a list of public key files to accept from the server"""
    pubkeys = {}

    def _set_from_config(self, attrs, cfg, section):
        """Does magic to take a list of strings specifying attributes, read
        their values from the config file, and set the members of that name to
        the read value."""
        
        # Go through all the attributes we have to set
        for attr in attrs:
            try:
                val = cfg.get(section, attr)
            except NoSectionError:
                # There's no such section, no point continuing as we'll just
                # keep getting this error
                return
            except NoOptionError:
                # There's no such option, go to the next attribute
                continue
            else:

                # If possible, evaluate the value as a python literal
                try:
                    val = ast.literal_eval(val)
                except ValueError:
                    # Not a python literal - just use the string
                    pass
                setattr(self, attr, val)

    def __init__(self, filename):
        """Constructor.  Reads a configuration in ini format from the given file
        and initialises the config with it."""
        cfg = RawConfigParser()
        cfg.read(filename)

        """@brief the name of the main section in the config file"""
        section = "raven"
        
        # See if we can get any of the attributes from the config file
        self._set_from_config(['login_url',
                               'logout_url',
                               'return_url',
                               'ver',
                               'max_clock_skew',
                               'timeout',
                               'aauth',
                               'iact',
                               'pubkeys'],
                              cfg,
                              section)

        # Read any certificates from the files
        for (name,filename) in self.pubkeys.iteritems():
            self.pubkeys[name] = X509.load_cert(filename, X509.FORMAT_PEM)
