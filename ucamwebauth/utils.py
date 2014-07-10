import time
import calendar

from string import maketrans
from base64 import b64decode
from urlparse import parse_qs

from django.conf import settings
from django.http import HttpResponseRedirect

from ucamwebauth.exceptions import MalformedResponseError


def decode_sig(sig):
    """Decodes a signature from the variant base64 used by raven.
    @param sig  A string giving the signature in Raven's variant base-64
    @return  A binary string containing the signature"""
    table = maketrans("-._", "+/=")
    sig = str(sig).translate(table)
    try:
        return b64decode(sig)
    except TypeError:
        raise MalformedResponseError("Signature is not a valid base-64 encoded string")


def setting(name, default=None):
    """Returns a setting from the Django settings file"""
    return getattr(settings, name, default)


def parse_time(time_string):
    """Converts a time of the form '20110729T123456Z' to a number of seconds
    since the epoch.
    @exception ValueError if the time is not a valid Raven time"""
    return calendar.timegm(time.strptime(time_string, "%Y%m%dT%H%M%SZ"))


def get_next_from_wls_response(response_str):
    tokens = response_str.split('!')
    params = parse_qs(tokens[11]) if tokens[0] == '3' else parse_qs(tokens[10])
    if 'next' in params:
        return params['next'][0]
    else:
        return None


class HttpResponseSeeOther(HttpResponseRedirect):
    """An HttpResponse with a 303 status code, since django doesn't provide one
    by default.  A 303 is required by the the WAA2WLS specification."""
    status_code = 303