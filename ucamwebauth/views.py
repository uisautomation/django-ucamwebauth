import urllib

from django.http import HttpResponseRedirect, HttpResponseForbidden
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import redirect
from django.utils.module_loading import import_by_path
from ucamwebauth import UserNotAuthorised
from ucamwebauth.utils import setting, HttpResponseSeeOther


def raven_return(request):
    # Get the token which the Raven server sent us - this should really
    # have a try/except around it to catch KeyError
    token = request.GET['WLS-Response']

    # See if this is a valid token
    try:
        user = authenticate(response_str=token)
    except UserNotAuthorised:
        unauthorised_view = import_by_path(setting('UCAMWEBAUTH_NOT_AUTHORISED',
                                                   default='ucamwebauth.views.default_unauthorised_user'))
        return unauthorised_view(request)

    if user is None:
        return redirect(setting('UCAMWEBAUTH_LOGOUT_REDIRECT', default='/'))
    else:
        login(request, user)
    
    # Redirect somewhere sensible
    return HttpResponseRedirect('/')


def default_unauthorised_user(request):
    return HttpResponseForbidden("Authentication successful but you are not authorised to access this site")


def raven_login(request):
    # Get the Raven object and return a redirect to the Raven server
    login_url = setting('UCAMWEBAUTH_LOGIN_URL')
    encoded_return_url = urllib.quote(setting('UCAMWEBAUTH_RETURN_URL'))
    return HttpResponseSeeOther("%s?ver=%d&url=%s" % (login_url, 3, encoded_return_url))


def raven_logout(request):
    logout(request)
    return redirect(setting('UCAMWEBAUTH_LOGOUT_REDIRECT', default='/'))
