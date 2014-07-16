import urllib
from django.http import HttpResponseRedirect
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import redirect
from ucamwebauth import MalformedResponseError
from ucamwebauth.utils import setting, HttpResponseSeeOther, get_next_from_wls_response


def raven_return(request):
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
    return_url = setting('UCAMWEBAUTH_RETURN_URL')
    desc = setting('UCAMWEBAUTH_DESC', default='')
    # aauth is ignored as v3 only supports 'pwd', therefore we do not need it.
    iact = setting('UCAMWEBAUTH_IACT', default='')
    msg = setting('UCAMWEBAUTH_MSG', default='')
    params = urllib.urlencode([('next', request.GET['next'])])
    fail = setting('UCAMWEBAUTH_FAIL', default='')
    msg = urllib.urlencode([('ver', 3), ('url', return_url), ('desc', desc),
                            ('iact', iact), ('msg', msg), ('params', params),
                            ('fail', fail)])
    return HttpResponseSeeOther("%s?%s" % (login_url, msg) )


def raven_logout(request):
    logout(request)
    return redirect(setting('UCAMWEBAUTH_LOGOUT_REDIRECT', default='/'))
