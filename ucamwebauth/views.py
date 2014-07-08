import urllib
from django.http import HttpResponseRedirect
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import redirect
from ucamwebauth.utils import setting, HttpResponseSeeOther


def raven_return(request):
    # Get the token which the Raven server sent us - this should really
    # have a try/except around it to catch KeyError
    token = request.GET['WLS-Response']

    # See if this is a valid token
    user = authenticate(response_str=token)

    if user is None:
        return redirect(setting('UCAMWEBAUTH_LOGOUT_REDIRECT', default='/'))
    else:
        login(request, user)
    
    # Redirect somewhere sensible
    return HttpResponseRedirect('/')


def raven_login(request):
    # Get the Raven object and return a redirect to the Raven server
    login_url = setting('UCAMWEBAUTH_LOGIN_URL')
    encoded_return_url = urllib.quote(setting('UCAMWEBAUTH_RETURN_URL'))
    desc = urllib.quote(setting('UCAMWEBAUTH_DESC', default=''))
    aauth = urllib.quote(setting('UCAMWEBAUTH_AAUTH', default=''))
    iact = urllib.quote(setting('UCAMWEBAUTH_IACT', default=''))
    msg = urllib.quote(setting('UCAMWEBAUTH_MSG', default=''))
    params = urllib.quote(setting('UCAMWEBAUTH_PARAMS', default=''))
    fail = urllib.quote(setting('UCAMWEBAUTH_FAIL', default=''))
    return HttpResponseSeeOther("%s?ver=%d&url=%s&desc=%s&aauth=%s&iact=%s&msg=%s&params=%s&fail=%s" %
                                (login_url, 3, encoded_return_url, desc, aauth, iact, msg, params, fail) )


def raven_logout(request):
    logout(request)
    return redirect(setting('UCAMWEBAUTH_LOGOUT_REDIRECT', default='/'))
