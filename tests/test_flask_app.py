from datetime import datetime
import calendar
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from nose.tools import raises
import jwt
import responses
import unittest

import app as flask_app

private_key = '''
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDexKjUIXzFV6Cfgt+eQrulNRJkKG6BjboDslLLilyizPNtVs9B
yvRVnDXAZBmmny26Remq70l9VXyaCeIHusyGCZuTzJ+z6xUa6obwU6kXM6QJR+kI
GApMtuyreRMhxAYyebvgYt7S8NPrpvvFor3K1RMSfTIA4SjQZXPv/VbMqwIDAQAB
AoGBAJW/j1oiNLSX5jK0EExbwbYZygYoI7jVI+EOQ5ftp74Mleq/O02X982A16U/
5Ppb8KpSCvTMLBOjnsIRuK7HhGmouiIW3H9IwZAFJ7yGSSlQ6js104cnDqMKWiu+
eig9rMQPKEStQqxGhWVvcZZmvLdlslVehbsVDBeuskdOIPfBAkEA+T2mqhjqQKTx
HY19sJyiz1WIJ4eE5BkpQwPi9mbj74XQABU1AY7ZXbVzvHsAYuEOJVMu7oeoah5p
uSwZip7NywJBAOTPOQx5+sownE50ZyMQpA1ym15GRuBY6Meto5/xZ5sSeQKosswv
TYSg5Q1Dh7c8OiLTIl/IR6fCI1fUrUl6IKECQQDol078N6oLz6EvagYcleAdynz4
HrC2SIDICE16koQt11tHaIMBxDQ3DglGoCa5H7sau+j1MmXJOj6BTpU7Vn1HAkAr
JwnTWI374/8WrM1mx5SpFJxIw2hKl3oPbqgVWin4DRvVbIuMBr/P66hHQB0waaNt
PfSVq+gXs32G6w1jdi0BAkEA8IUP5Nthi4gEQ6VVvcocxITswPSgIXSrWlzrdpBl
zWuB3EAOQrHd+1Ks7R887uNs6Yce96COoADys2mkd2eKMg==
-----END RSA PRIVATE KEY-----
'''

public_key = '''
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDexKjUIXzFV6Cfgt+eQrulNRJk
KG6BjboDslLLilyizPNtVs9ByvRVnDXAZBmmny26Remq70l9VXyaCeIHusyGCZuT
zJ+z6xUa6obwU6kXM6QJR+kIGApMtuyreRMhxAYyebvgYt7S8NPrpvvFor3K1RMS
fTIA4SjQZXPv/VbMqwIDAQAB
-----END PUBLIC KEY-----
'''


class TestFlaskApp(unittest.TestCase):

    def setUp(self):
        self.app = flask_app.app.test_client()
        self.okta = {
            'base_url': 'https://example.okta.com',
            'api_token': '01A2bCd3efGh-ij-4K-Lmn5OPqrSTuvwXYZaBCD6EF',
            'client_id': 'a0bcdEfGhIJkLmNOPQr1',
            }
        flask_app.okta = self.okta
        flask_app.public_key = serialization.load_pem_public_key(
            public_key,
            backend=default_backend())

    def tearDown(self):
        pass

    def create_jwt(self, claim={}):
        # http://stackoverflow.com/a/16755432/3191847
        d = datetime.utcnow()
        iat = int(calendar.timegm(d.utctimetuple()))
        exp = iat + 3600
        defaults = {
            "sub": "00u0abcdefGHIJKLMNOP",
            "ver": 1,
            "iss": "https://example.okta.com",
            "login": "username@example.com",
            "aud": self.okta['client_id'],
            "iat": iat,
            "exp": exp,
            "amr": [
                "pwd"
            ],
            "idp": "00o0abcde1FGHIJKLMNO",
            "jti": "abcD0eFgHIJKLmnOPQ1r",
            "auth_time": iat
        }
        for key in claim.keys():
            defaults[key] = claim[key]
        return jwt.encode(defaults, private_key, algorithm='RS256')

    def test_has_default_route(self):
        path = "/"
        rv = self.app.get(path)
        self.assertEquals("200 OK", rv.status)
        self.assertIn("<html", rv.data)

    def test_sso_via_id_token(self):
        id_token = self.create_jwt()
        print id_token
        rv = self.app.post('/sso/oidc', data={'id_token': id_token})
        self.assertIn("Set-Cookie", rv.headers)
        self.assertIn("session=", rv.headers['Set-Cookie'])
        self.assertEquals("302 FOUND", rv.status)
    
    def test_sso_via_id_token_invalid(self):
        id_token = self.create_jwt({'aud': 'invalid'})
        print id_token
        rv = self.app.post('/sso/oidc', data={'id_token': id_token})
        self.assertEquals("500 INTERNAL SERVER ERROR", rv.status)

    def test_parse_jwt_valid(self):
        id_token = self.create_jwt({})
        rv = flask_app.parse_jwt(id_token)
        self.assertEquals('00u0abcdefGHIJKLMNOP', rv['sub'])

    @raises(jwt.InvalidAudienceError)
    def test_parse_jwt_invalid_audience(self):
        id_token = self.create_jwt({'aud': 'INVALID'})
        flask_app.parse_jwt(id_token)

    @raises(jwt.InvalidIssuerError)
    def test_parse_jwt_invalid_issuer(self):
        id_token = self.create_jwt({'iss': 'INVALID'})
        flask_app.parse_jwt(id_token)

    @responses.activate
    def test_login_with_password(self):
        sessionToken = 'FAKE_SESSION_TOKEN'
        responses.add(
            responses.POST,
            'https://example.okta.com/api/v1/authn',
            json.dumps({'sessionToken': sessionToken}),
            status=200)
        data = {
            'username': 'username',
            'password': 'password',
            }
        rv = self.app.post('/login', data=data)
        self.assertEquals("302 FOUND", rv.status)
        self.assertIn('LOCATION', rv.headers)
        self.assertIn(sessionToken, rv.headers['Location'])
