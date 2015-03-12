from django.http import HttpResponseRedirect
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import redirect
try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode
from ucamwebauth import MalformedResponseError
from ucamwebauth.utils import setting, HttpResponseSeeOther, get_next_from_wls_response, get_return_url


def raven_return(request):
    try:
        token = request.GET['WLS-Response']
    except KeyError:
        raise MalformedResponseError("no WLS-Response")

    # See if this is a valid token
    user = authenticate(response_req=request)

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
    return_url = get_return_url(request)
    desc = setting('UCAMWEBAUTH_DESC', default='')
    # aauth is ignored as v3 only supports 'pwd', therefore we do not need it.
    iact = setting('UCAMWEBAUTH_IACT', default='')
    msg = setting('UCAMWEBAUTH_MSG', default='')
    fail = setting('UCAMWEBAUTH_FAIL', default='')
    next_p = request.GET.get('next', None)
    if next_p is not None:
        params = urlencode([('next', next_p)])
        msg = urlencode([('ver', 3), ('url', return_url), ('desc', desc), ('iact', iact), ('msg', msg),
                         ('params', params), ('fail', fail)])
    else:
        msg = urlencode([('ver', 3), ('url', return_url), ('desc', desc), ('iact', iact), ('msg', msg),
                         ('fail', fail)])

    return HttpResponseSeeOther("%s?%s" % (login_url, msg))


def raven_logout(request):
    logout(request)
    return redirect(setting('UCAMWEBAUTH_LOGOUT_REDIRECT', default='/'))
