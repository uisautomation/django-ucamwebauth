import urllib

from django.contrib.auth import authenticate, login
from django.contrib.auth import logout

from pyroven.utils import setting, HttpResponseSeeOther

def pyroven_return(request):
    # Get the token which the Raven server sent us - this should really
    # have a try/except around it to catch KeyError
    token = request.GET['WLS-Response']
    # See if this is a valid token
    user = authenticate(response_str=token)
    if user is None:
        # Some sort of err
    else:
        login(request, user)
    # Redirect somewhere sensible
    return HttpResponseRedirect('/')

def pyroven_login(request):
    # Get the Raven object and return a redirect to the Raven server
    login_url = setting(RAVEN_LOGIN_URL)
    encoded_return_url = urllib.quote(setting(RAVEN_RETURN_URL))
    return HttpResponseSeeOther("%s?ver=%d&url=%s" % (login_url, 2, 
                                                      encoded_return_url)
                               )

def pyroven_logout(request):
    logout(request)
