[![Build Status](https://travis-ci.org/abrahammartin/django-ucamwebauth.svg?branch=master)](https://travis-ci.org/abrahammartin/django-ucamwebauth)

# Introduction

django-ucamwebauth is a library which provides use of Cambridge University's 
[Raven authentication](http://raven.cam.ac.uk/) for [Django](https://www.djangoproject.com/). It provides a Django 
authentication backend which can be added to `AUTHENTICATION_BACKENDS` in the Django `settings` module.

## Use

Install django-ucamwebauth using pip:

```bash
pip install django-ucamwebauth
```

Then you can enable it within your Django project's settings.py:

```python
AUTHENTICATION_BACKENDS = (
    'ucamwebauth.backends.RavenAuthBackend',
    'django.contrib.auth.backends.ModelBackend'
)
```

This allows both normal Django login and Raven login.

You should then enable the URLs for ucamwebauth:

````python
urlpatterns = patterns('',
    ...
    url(r'', include('ucamwebauth.urls')),
    ...
)
````

## Minimum Config Settings

You then need to configure the app's settings. Raven has a live and test environments, the URL and certificate details 
are given below.

There are four minimum config settings:

```
UCAMWEBAUTH_LOGIN_URL: a string representing the URL for the Raven login redirect.
UCAMWEBAUTH_LOGOUT_URL: a string representing the logout URL for Raven.
UCAMWEBAUTH_RETURN_URL: the URL of your app which the Raven service should return the user to after authentication.
    (Default is generated automatically from the urlconf)
UCAMWEBAUTH_LOGOUT_REDIRECT: a string representing the URL to where the user is redirected when she logs out of the app
    (Default to '/').
UCAMWEBAUTH_NOT_CURRENT: a boolean value representing if raven users that are currently not members of the university
    should be allowed to log in (Default to False). More info: http://www.ucs.cam.ac.uk/accounts/ravenleaving
UCAMWEBAUTH_CERTS: a dictionary including key names and their associated certificates which can be downloaded from the
    Raven project pages.
UCAMWEBAUTH_TIMEOUT: An integer with the time (in seconds) that has to pass to consider an authentication timed out
    (Default to 30).
UCAMWEBAUTH_REDIRECT_AFTER_LOGIN: The url where you want to redirect the user after login (Default to '/').
UCAMWEBAUTH_CREATE_USE: This defaults to True, allowing the autocreation of users who have been successfully 
authenticated by Raven, but do not exist in the local database. The user is created with set_unusable_password().
```

An example, referencing the Raven test environment is given below:

```python
UCAMWEBAUTH_LOGIN_URL = 'https://demo.raven.cam.ac.uk/auth/authenticate.html'
UCAMWEBAUTH_LOGOUT_URL = 'https://demo.raven.cam.ac.uk/auth/logout.html'
UCAMWEBAUTH_LOGOUT_REDIRECT = 'http://www.cam.ac.uk/'
UCAMWEBAUTH_CERTS = {901: """-----BEGIN CERTIFICATE-----
MIIDzTCCAzagAwIBAgIBADANBgkqhkiG9w0BAQQFADCBpjELMAkGA1UEBhMCR0Ix
EDAOBgNVBAgTB0VuZ2xhbmQxEjAQBgNVBAcTCUNhbWJyaWRnZTEgMB4GA1UEChMX
VW5pdmVyc2l0eSBvZiBDYW1icmlkZ2UxLTArBgNVBAsTJENvbXB1dGluZyBTZXJ2
aWNlIERFTU8gUmF2ZW4gU2VydmljZTEgMB4GA1UEAxMXUmF2ZW4gREVNTyBwdWJs
aWMga2V5IDEwHhcNMDUwNzI2MTMyMTIwWhcNMDUwODI1MTMyMTIwWjCBpjELMAkG
A1UEBhMCR0IxEDAOBgNVBAgTB0VuZ2xhbmQxEjAQBgNVBAcTCUNhbWJyaWRnZTEg
MB4GA1UEChMXVW5pdmVyc2l0eSBvZiBDYW1icmlkZ2UxLTArBgNVBAsTJENvbXB1
dGluZyBTZXJ2aWNlIERFTU8gUmF2ZW4gU2VydmljZTEgMB4GA1UEAxMXUmF2ZW4g
REVNTyBwdWJsaWMga2V5IDEwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALhF
i9tIZvjYQQRfOzP3cy5ujR91ZntQnQehldByHlchHRmXwA1ot/e1WlHPgIjYkFRW
lSNcSDM5r7BkFu69zM66IHcF80NIopBp+3FYqi5uglEDlpzFrd+vYllzw7lBzUnp
CrwTxyO5JBaWnFMZrQkSdspXv89VQUO4V4QjXV7/AgMBAAGjggEHMIIBAzAdBgNV
HQ4EFgQUgjC6WtA4jFf54kxlidhFi8w+0HkwgdMGA1UdIwSByzCByIAUgjC6WtA4
jFf54kxlidhFi8w+0HmhgaykgakwgaYxCzAJBgNVBAYTAkdCMRAwDgYDVQQIEwdF
bmdsYW5kMRIwEAYDVQQHEwlDYW1icmlkZ2UxIDAeBgNVBAoTF1VuaXZlcnNpdHkg
b2YgQ2FtYnJpZGdlMS0wKwYDVQQLEyRDb21wdXRpbmcgU2VydmljZSBERU1PIFJh
dmVuIFNlcnZpY2UxIDAeBgNVBAMTF1JhdmVuIERFTU8gcHVibGljIGtleSAxggEA
MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAsdyB+9szctHHIHE+S2Kg
LSxbGuFG9yfPFIqaSntlYMxKKB5ba/tIAMzyAOHxdEM5hi1DXRsOok3ElWjOw9oN
6Psvk/hLUN+YfC1saaUs3oh+OTfD7I4gRTbXPgsd6JgJQ0TQtuGygJdaht9cRBHW
wOq24EIbX5LquL9w+uvnfXw=
-----END CERTIFICATE-----
"""}
```

## Errors

There are five possible exceptions that can be raised using this module: MalformedResponseError, InvalidResponseError,
PublicKeyNotFoundError, and OtherStatusCode that return HTTP 500, or UserNotAuthorised that returns 403. You can catch 
these exceptions using process_exception middleware 
(https://docs.djangoproject.com/en/1.7/topics/http/middleware/#process_exception) to customize what the user will 
receive as a response. The module has a default behaviour for these exceptions with HTTP error codes and using their 
corresponding templates. To use the default behaviour just add:
 
```python
MIDDLEWARE_CLASSES = (
    ...
    'ucamwebauth.middleware.DefaultErrorBehaviour',
    ...
)

INSTALLED_APPS = (
    ...
    'ucamwebauth',
    ...
)
```

You can also rewrite the ucamwebauth_\<httpcode\>.html templates. You only need to add the following lines to your own if 
you want to show the user the error message:

```python
{% for message in messages %}
    {{ message }}<br/>
{% endfor %}
```


## Authentication request parameters

This parameters are sent with the authentication request and allows the developer to tune the request to fit their app:

```
UCAMWEBAUTH_DESC: A text description of the resource requesting authentication which may be displayed to the end-user
    to further identify the resource to which his/her identity is being disclosed. Can be omitted.
UCAMWEBAUTH_IACT: The value 'yes' requires that a re-authentication exchange takes place with the user. This could be
    used prior to a sensitive transaction in an attempt to ensure that a previously authenticated user is still present
    at the browser. The value 'no' requires that the authentication request will only succeed if the user's identity
    can be returned without interacting with the user. This could be used as an optimisation to take advantage of any
    existing authentication but without actively soliciting one. If omitted or empty, then a previously established
    identity may be returned if the WLS supports doing so, and if not then the user will be prompted as necessary.
UCAMWEBAUTH_MSG: Text describing why authentication is being requested on this occasion which may be displayed to the
    end-user. Can be omitted.
UCAMWEBAUTH_PARAMS: Data that will be returned unaltered to the WAA in any 'authentication response message' issued as
    a result of this request. This could be used to carry the identity of the resource originally requested or other
    WAA state, or to associate authentication requests with their eventual replies. When returned, this data will be
    protected by the digital signature applied to the authentication response message but nothing else is done to
    ensure the integrity or confidentiality of this data - the WAA MUST take responsibility for this if necessary.
UCAMWEBAUTH_FAIL: If this parameter is 'yes' and the outcome of the request is anything other than success (i.e. the
    status code would be anything other than 200) then the WLS MUST return an informative error to the user and MUST
    not redirect back to the WAA. Setting this makes it easier to implement WAAs at the expense of a loss of
    flexibility in error handling.
```

The details of these can be found in the Raven WLS protocol documentation,
[here](http://raven.cam.ac.uk/project/waa2wls-protocol.txt).
