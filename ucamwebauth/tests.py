"""ucamwebauth.tests

Contains tests for the ucamwebauth application
"""

from datetime import datetime, timedelta
from base64 import b64encode
from string import maketrans
import urllib
import requests
from OpenSSL.crypto import FILETYPE_PEM, load_privatekey, sign

from django.conf import settings
from django.test import TestCase
from django.test.client import Client
from django.core.urlresolvers import reverse
from django.contrib.auth.models import User


from ucamwebauth import InvalidResponseError, MalformedResponseError, setting, UserNotAuthorised

RAVEN_TEST_USER = 'test0001'
RAVEN_TEST_PWD = 'test'
RAVEN_NEW_USER = 'test0002'

RAVEN_RETURN_URL = setting('UCAMWEBAUTH_RETURN_URL')

GOOD_PRIV_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQC4RYvbSGb42EEEXzsz93Mubo0fdWZ7UJ0HoZXQch5XIR0Zl8AN
aLf3tVpRz4CI2JBUVpUjXEgzOa+wZBbuvczOuiB3BfNDSKKQaftxWKouboJRA5ac
xa3fr2JZc8O5Qc1J6Qq8E8cjuSQWlpxTGa0JEnbKV7/PVUFDuFeEI11e/wIDAQAB
AoGACr2jBUkXF3IjeAnE/aZyxEYVW7wQGSf9vzAf92Jvekyn0ZIS07VC4+FiPlqF
93QIFaJmVwVOAA5guztaStgtU9YX37wRPkFwrtKgjZcqV8ReQeC67bjo5v3Odht9
750F7mKWXctZrm0MD1PoDlkLvVZ2hDolHm5tpfP52jPvQ6ECQQDgtI4K3IuEVOIg
75xUG3Z86DMmwPmme7vsFgf2goWV+p4471Ang9oN7l+l+Jj2VISdz7GE7ZQwW6a1
IQev3+h7AkEA0e9oC+lCcYsMsI9vtXvB8s6Bpl0c1U19HUUWHdJIpluwvxF6SIL3
ug4EJPP+sDT5LvdV5cNy7nmO9uUd+Se2TQJAdxI2UrsbkzwHt7xA8rC60OWadWa8
4+OdaTUjcxUnBJqRTUpDBy1vVwKB3MknBSE0RQvR3canSBjI9iJSmHfmEQJAKJlF
49fOU6ryX0q97bjrPwuUoxmqs81yfrCXoFjEV/evbKPypAc/5SlEv+i3vlfgQKbw
Y6iyl0/GyBRzAXYemQJAVeChw15Lj2/uE7HIDtkqd8POzXjumOxKPfESSHKxRGnP
3EruVQ6+SY9CDA1xGfgDSkoFiGhxeo1lGRkWmz09Yw==
-----END RSA PRIVATE KEY-----
"""

BAD_PRIV_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQD5mkLpi7q6ROdu7khB3S9aanA0Zls7vvfGOmB80/yeylhGpsjA
jWen0VtSQke/NlEPGtO38tsV7CsuFnSmschvAnGrcJl76b0UOOHUgDTIoRxC6QDU
3claegwsrBA+sJEBbqx5RdXbIRGicPG/8qQ4Zm1SKOgotcbwiaor2yxZ2wIDAQAB
AoGBAPCgMpmLxzwDaUmcFbTJUvlLW1hoxNNYSu2jIZm1k/hRAcE60JYwvBkgz3UB
yMEh0AtLxYe0bFk6EHah11tMUPgscbCq73snJ++8koUw+csk22G65hOs51bVb7Aa
6JBe67oLzdtvgCUFAA2qfrKzWRZzAdhUirQUZgySZk+Xq1pBAkEA/kZG0A6roTSM
BVnx7LnPfsycKUsTumorpXiylZJjTi9XtmzxhrYN6wgZlDOOwOLgSQhszGpxVoMD
u3gByT1b2QJBAPtL3mSKdvwRu/+40zaZLwvSJRxaj0mcE4BJOS6Oqs/hS1xRlrNk
PpQ7WJ4yM6ZOLnXzm2mKyxm50Mv64109FtMCQQDOqS2KkjHaLowTGVxwC0DijMfr
I9Lf8sSQk32J5VWCySWf5gGTfEnpmUa41gKTMJIbqZZLucNuDcOtzUaeWZlZAkA8
ttXigLnCqR486JDPTi9ZscoZkZ+w7y6e/hH8t6d5Vjt48JVyfjPIaJY+km58LcN3
6AWSeGAdtRFHVzR7oHjVAkB4hutvxiOeiIVQNBhM6RSI9aBPMI21DoX2JRoxvNW2
cbvAhow217X9V0dVerEOKxnNYspXRrh36h7k4mQA+sDq
-----END RSA PRIVATE KEY-----
"""


def create_wls_response(raven_ver='3', raven_status='200', raven_msg='',
                        raven_issue=datetime.utcnow().strftime('%Y%m%dT%H%M%SZ'),
                        raven_id='1347296083-8278-2', 
                        raven_url=RAVEN_RETURN_URL,
                        raven_principal=RAVEN_TEST_USER, raven_ptags='current',
                        raven_auth='pwd', raven_sso='', raven_life='36000',
                        raven_params='', raven_kid='901',
                        raven_key_pem=GOOD_PRIV_KEY_PEM):
    """Creates a valid WLS Response as the Raven test server would 
    using keys from https://raven.cam.ac.uk/project/keys/demo_server/
    """
    raven_pkey = load_privatekey(FILETYPE_PEM, raven_key_pem) 
    trans_table = maketrans("+/=", "-._")

    # This is the data which is signed by Raven with their private key
    # Note data consists of full payload with exception of kid and sig
    # source: http://raven.cam.ac.uk/project/waa2wls-protocol-3.0.txt
    wls_response_data = [raven_ver, raven_status, raven_msg, 
                         raven_issue, raven_id, raven_url, 
                         raven_principal, raven_ptags, raven_auth,
                         raven_sso, raven_life, raven_params]
    
    data = '!'.join(wls_response_data)
    raven_sig = b64encode(sign(raven_pkey, data, 'sha1'))

    # Full WLS-Response also includes the Raven-variant b64encoded sig
    # and the requisite Key ID which has been used for the signing 
    # process
    wls_response_data.append(raven_kid)
    wls_response_data.append(str(raven_sig).translate(trans_table))

    return '!'.join(wls_response_data)


class RavenTestCase(TestCase):
    """RavenTestCase
    Authentication tests for the Raven service
    """

    fixtures = ['users.json']

    def __init__(self, *args, **kwargs):
        self.client = Client()
        super(RavenTestCase, self).__init__(*args, **kwargs)

    def do_login(self):
        response = requests.post('https://demo.raven.cam.ac.uk/auth/authenticate2.html',
                                 {'url': settings.UCAMWEBAUTH_RETURN_URL,
                                  'userid': 'test0001', 'pwd': 'test',
                                  'ver': '3'}, allow_redirects=False)
        self.assertEqual(303, response.status_code)
        redirect_url = urllib.unquote(response.headers['location'])
        self.client.get(reverse('raven_return'), {'WLS-Response': redirect_url.split('WLS-Response=')[1]})

    def test_real_raven_test_service(self):
        self.do_login()
        self.assertIn('_auth_user_id', self.client.session)

    def test_login_raven_not_local(self):
        """Tests login of user via raven, not in database"""
        with self.settings(UCAMWEBAUTH_CREATE_USER=False):
            self.client.get(reverse('raven_return'),
                            {'WLS-Response': create_wls_response(raven_principal=RAVEN_NEW_USER)})
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_login_raven_local(self):
        """Tests login of user who exists in database"""
        self.client.get(reverse('raven_return'), {'WLS-Response': create_wls_response()})
        self.assertIn('_auth_user_id', self.client.session)

    def test_login_invalid_version_fails(self):
        with self.assertRaises(MalformedResponseError) as excep:
            self.client.get(reverse('raven_return'), {'WLS-Response': create_wls_response(raven_ver='1')})
        self.assertEqual(str(excep.exception), 'Unsupported version: 1')
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_login_invalid_version_fails_with_template(self):
        with self.settings(
                MIDDLEWARE_CLASSES=(
                    'django.contrib.sessions.middleware.SessionMiddleware',
                    'django.middleware.common.CommonMiddleware',
                    'django.middleware.csrf.CsrfViewMiddleware',
                    'django.contrib.auth.middleware.AuthenticationMiddleware',
                    'django.contrib.messages.middleware.MessageMiddleware',
                    'django.middleware.clickjacking.XFrameOptionsMiddleware',
                    'ucamwebauth.middleware.DefaultErrorBehaviour',
                )):
            response = self.client.get(reverse('raven_return'), {'WLS-Response': create_wls_response(raven_ver='1')})
        self.assertContains(response, 'Unsupported version: 1', status_code=500)
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_login_issue_future_fails(self):
        """Tests that Raven responses issued in the future fail validation"""
        with self.assertRaises(InvalidResponseError) as excep:
            self.client.get(reverse('raven_return'),
                            {'WLS-Response': create_wls_response(
                                raven_issue=(datetime.utcnow() + timedelta(hours=1)).strftime('%Y%m%dT%H%M%SZ'))})
        self.assertEqual(str(excep.exception), 'The timestamp on the response is in the future')
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_login_issue_future_fails_with_template(self):
        """Tests that Raven responses issued in the future fail validation"""
        with self.settings(
                MIDDLEWARE_CLASSES=(
                    'django.contrib.sessions.middleware.SessionMiddleware',
                    'django.middleware.common.CommonMiddleware',
                    'django.middleware.csrf.CsrfViewMiddleware',
                    'django.contrib.auth.middleware.AuthenticationMiddleware',
                    'django.contrib.messages.middleware.MessageMiddleware',
                    'django.middleware.clickjacking.XFrameOptionsMiddleware',
                    'ucamwebauth.middleware.DefaultErrorBehaviour',
                )):
            response = self.client.get(reverse('raven_return'),
                                       {'WLS-Response': create_wls_response(
                                           raven_issue=(datetime.utcnow() +
                                                        timedelta(hours=1)).strftime('%Y%m%dT%H%M%SZ'))})
        self.assertContains(response, 'The timestamp on the response is in the future', status_code=500)
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_login_issue_too_old_fails(self):
        """Tests that Raven responses which are older than UCAMWEBAUTH_TIMEOUT are rejected"""
        with self.assertRaises(InvalidResponseError) as excep:
            self.client.get(reverse('raven_return'),
                            {'WLS-Response': create_wls_response(
                                raven_issue=(datetime.utcnow() + timedelta(hours=-1)).strftime('%Y%m%dT%H%M%SZ'))})
        self.assertTrue(str(excep.exception).startswith('Response has timed out'))
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_login_wrong_private_key_fails(self):
        """Tests that Raven responses with invalid key fail"""
        with self.assertRaises(InvalidResponseError) as excep:
            self.client.get(reverse('raven_return'),
                            {'WLS-Response': create_wls_response(raven_key_pem=BAD_PRIV_KEY_PEM)})
        self.assertEqual(str(excep.exception), 'The signature for this response is not valid.')
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_create_raven_not_local_create_false(self):
        """When valid raven user authenticates, and UCAMWEBAUTH_CREATE_USER is
        false, user is not created in database"""
        with self.settings(UCAMWEBAUTH_CREATE_USER=False):
            self.client.get(reverse('raven_return'),
                            {'WLS-Response': create_wls_response(raven_principal=RAVEN_NEW_USER)})
            with self.assertRaises(User.DoesNotExist):
                User.objects.get(username=RAVEN_NEW_USER)
            self.assertNotIn('_auth_user_id', self.client.session)

    def test_raven_user_not_local_create_true(self):
        """When valid raven user authenticates, and UCAMWEBAUTH_CREATE_USER is true
        creates valid user in database"""
        with self.settings(UCAMWEBAUTH_CREATE_USER=True):
            self.client.get(reverse('raven_return'),
                            {'WLS-Response': create_wls_response(raven_principal=RAVEN_NEW_USER)})
            user = User.objects.get(username=RAVEN_NEW_USER)
            self.assertFalse(user.has_usable_password())

    def test_logout_redirect_url(self):
        """Tests the logout redirection"""
        self.client.get(reverse('raven_return'), {'WLS-Response': create_wls_response()})
        self.assertIn('_auth_user_id', self.client.session)
        with self.settings(UCAMWEBAUTH_LOGOUT_REDIRECT='http://www.cam.ac.uk/'):
            response = self.client.get(reverse('raven_logout'), follow=True)
            self.assertEqual('http://www.cam.ac.uk/', response.redirect_chain[0][0])
            self.assertEqual(302, response.redirect_chain[0][1])

    def test_not_allow_raven_for_life(self):
        """Test Raven for life accounts credentials"""
        with self.assertRaises(UserNotAuthorised) as excep:
            self.client.get(reverse('raven_return'), {'WLS-Response': create_wls_response(raven_ptags='')})
        self.assertEqual(str(excep.exception), 'Authentication successful but you are not authorised to access this '
                                               'site')

    def test_not_allow_raven_for_life_with_template(self):
        """Test Raven for life accounts credentials"""
        with self.settings(
                MIDDLEWARE_CLASSES=(
                    'django.contrib.sessions.middleware.SessionMiddleware',
                    'django.middleware.common.CommonMiddleware',
                    'django.middleware.csrf.CsrfViewMiddleware',
                    'django.contrib.auth.middleware.AuthenticationMiddleware',
                    'django.contrib.messages.middleware.MessageMiddleware',
                    'django.middleware.clickjacking.XFrameOptionsMiddleware',
                    'ucamwebauth.middleware.DefaultErrorBehaviour',
                )):
            response = self.client.get(reverse('raven_return'), {'WLS-Response': create_wls_response(raven_ptags='')})
        self.assertContains(response, 'Authentication successful but you are not authorised to access this site',
                            status_code=403)

    def test_allow_raven_for_life(self):
        with self.settings(UCAMWEBAUTH_NOT_CURRENT=True):
            self.client.get(reverse('raven_return'), {'WLS-Response': create_wls_response(raven_ptags='')})
            self.assertIn('_auth_user_id', self.client.session)