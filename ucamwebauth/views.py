import urllib
from django.http import HttpResponseRedirect
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import redirect
from ucamwebauth import MalformedResponseError
from ucamwebauth.utils import setting, HttpResponseSeeOther, get_next_from_wls_response


def raven_return(request):
    # Get the token which the Raven server sent us - this should really
    # have a try/except around it to catch KeyError
    try:
        token = request.GET['WLS-Response']
    except Exception:
        raise MalformedResponseError("no WLS-Response")

    # See if this is a valid token
    user = authenticate(response_str=token)

    if user is None:
        return redirect(setting('UCAMWEBAUTH_LOGOUT_REDIRECT', default='/'))
    else:
        login(request, user)
    
    # Redirect somewhere sensible

    redirect_url = get_next_from_wls_response(token)

    if redirect_url is not None and setting('UCAMWEBAUTH_REDIRECT_AFTER_LOGIN', default=None) is None:
        return HttpResponseRedirect(redirect_url)
    else:
        return HttpResponseRedirect(setting('UCAMWEBAUTH_REDIRECT_AFTER_LOGIN', default='/'))


def raven_login(request):
    # Get the Raven object and return a redirect to the Raven server
    login_url = setting('UCAMWEBAUTH_LOGIN_URL')
    encoded_return_url = urllib.quote(setting('UCAMWEBAUTH_RETURN_URL'))
    desc = urllib.quote(setting('UCAMWEBAUTH_DESC', default=''))
    # aauth is ignored as v3 only supports 'pwd', therefore we do not need it.
    iact = urllib.quote(setting('UCAMWEBAUTH_IACT', default=''))
    msg = urllib.quote(setting('UCAMWEBAUTH_MSG', default=''))
    params = urllib.quote('next=' + request.GET['next'])
    fail = urllib.quote(setting('UCAMWEBAUTH_FAIL', default=''))
    return HttpResponseSeeOther("%s?ver=%d&url=%s&desc=%s&iact=%s&msg=%s&params=%s&fail=%s" %
                                (login_url, 3, encoded_return_url, desc, iact, msg, params, fail) )


def raven_logout(request):
    logout(request)
    return redirect(setting('UCAMWEBAUTH_LOGOUT_REDIRECT', default='/'))
