"""pyroven.tests

Contains tests for the pyroven application
"""

from datetime import datetime
from base64 import b64encode
from string import maketrans

from django.test import TestCase
from django.test.client import Client
from django.core.urlresolvers import reverse
from django.contrib.auth.models import User

from OpenSSL.crypto import FILETYPE_PEM, load_privatekey, sign

RAVEN_TEST_USER = 'test0001'
RAVEN_TEST_PWD = 'test'
RAVEN_NEW_USER = 'test0002'

RAVEN_TEST_PRIVATE_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
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

def create_wls_response(principal=RAVEN_TEST_USER):
    """Creates a valid WLS Response as the Raven test server would 
    using keys from https://raven.cam.ac.uk/project/keys/demo_server/
    """
    raven_pkey = load_privatekey(FILETYPE_PEM, 
                                 RAVEN_TEST_PRIVATE_KEY_PEM) 
    trans_table = maketrans("+/=", "-._")

    # Raven variables from which make up valid WLS-Response
    raven_ver = '2'
    raven_status = '200'
    raven_msg = ''
    raven_issue = datetime.now().strftime('%Y%m%dT%H%M%SZ')
    raven_id = '1347296083-8278-2'
    raven_url = 'http%3A%2F%2Fwww.example.org%2Fraven_return%2F'
    raven_principal = principal
    raven_auth = 'pwd'
    raven_sso = ''
    raven_life = '36000'
    raven_params = ''
    raven_kid = '901'

    # This is the data which is signed by Raven with their private key
    # Note data consists of full payload with exception of kid and sig
    # source: http://raven.cam.ac.uk/project/waa2wls-protocol.txt
    wls_response_data = [raven_ver, raven_status, raven_msg, 
                         raven_issue, raven_id, raven_url, 
                         raven_principal, raven_auth, raven_sso, 
                         raven_life, raven_params]
    
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

    def test_login_raven_not_local(self):
        """Tests login of user via raven, not in database"""
        response = self.client.get(reverse('raven_return'), 
                        {'WLS-Response': create_wls_response(
                            principal=RAVEN_NEW_USER)})
        
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_login_raven_local(self):
        """Tests login of user who exists in database"""
        response = self.client.get(reverse('raven_return'), 
                        {'WLS-Response': create_wls_response()})

        self.assertIn('_auth_user_id', self.client.session)

    def test_create_raven_not_local_create_false(self):
        """When valid raven user authenticates, and PYROVEN_CREATE_USER is 
        false, user is not created in database"""

        with self.settings(PYROVEN_CREATE_USER=False):
            response = self.client.get(reverse('raven_return'), 
                        {'WLS-Response': create_wls_response(
                            principal=RAVEN_NEW_USER)})

            with self.assertRaises(User.DoesNotExist):
                User.objects.get(username=RAVEN_NEW_USER)

    def test_raven_user_not_local_create_true(self):
        """When valid raven user authenticates, and PYROVEN_CREATE_USER is true
        creates valid user in database"""

        with self.settings(PYROVEN_CREATE_USER=True):
            response = self.client.get(reverse('raven_return'), 
                        {'WLS-Response': create_wls_response(
                            principal=RAVEN_NEW_USER)})

            user = User.objects.get(username=RAVEN_NEW_USER)
            
            self.assertFalse(user.has_usable_password())
