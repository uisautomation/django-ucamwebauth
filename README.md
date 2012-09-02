# Introduction

pyroven is a library which provides [Raven authentication](http://raven.cam.ac.uk/) for [Django](https://www.djangoproject.com/). It provides a Django authentication backend which can be added to `AUTHENTICATION_BACKENDS` in the Django `settings` module:

````python
AUTHENTICATION_BACKENDS = (
    'pyroven.pyroven_django.RavenAuthBackend',
    'django.contrib.auth.backends.ModelBackend'
)
````

This allows both normal Django login and Raven login.

Anything using pyroven should make sure that the configuration is loaded; this is done by setting the config variable in the Raven singleton class:

````python
from pyroven import RavenConfig
from pyroven.pyroven_django import Raven
def configure():
    r = Raven()
    if r.config is None:
        r.config = RavenConfig("raven.ini")
````

The login page should redirect users to Raven:

````python
def raven_login(request):
    # Ensure we're properly configured
    configure()
    # Get the Raven object and return a redirect to the Raven server
    r = Raven()
    return r.get_login_redirect()
````

When the user has authenticated with Raven, the Raven server will redirect them back to your site (the exact URL is specified in the `.ini` file above). The return page should call the Django `authenticate` and `login` functions with a token received from the Raven server via HTTP GET:

````python
from django.contrib.auth import authenticate, login

def raven_return(request):
    # Ensure we're properly configured
    configure()

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
````

The `.ini` file which the Raven settings are loaded from has the following format:

````ini
[raven]
login_url = "http://raven.cam.ac.uk/auth/authenticate.html"
logout_url = "http://raven.cam.ac.uk/auth/logout.html"
return_url = "http://your.server.cam.ac.uk/ravenreturn/"
pubkeys = {'2':'/path/to/pubkey2.crt'}
````

The Raven service also offers a test server for authenticating accounts whilst testing implementations of Raven authentication. Test accounts use the usernames test0001 to test0500, with the password 'test' used throughout. The keys and certificates for this server can be retrieved from [Demonstration Server Keys](https://raven.cam.ac.uk/project/keys/demo_server/).

The relevant ini settings to use this are:

````ini
[raven]
login_url = "https://demo.raven.cam.ac.uk/auth/authenticate.html"
logout_url = "https://demo.raven.cam.ac.uk/auth/logout.html"
return_url = "http://your.server.cam.ac.uk/ravenreturn/"
pubkeys = {'901':'/path/to/pubkey901.crt'}
