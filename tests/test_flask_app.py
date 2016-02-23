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

certificate = '''
-----BEGIN CERTIFICATE-----
MIICITCCAYqgAwIBAgIJAPvk/teL+BzRMA0GCSqGSIb3DQEBBQUAMBYxFDASBgNV
BAMTC2V4YW1wbGUuY29tMB4XDTE2MDIyMzAwNTg1M1oXDTE3MDIyMjAwNTg1M1ow
FjEUMBIGA1UEAxMLZXhhbXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ
AoGBANisgEmNjzbaEv3Qpu8bP8V9utRsN8JxJxzUjNSf3k7Uj4BfAFfJpKHQcmFc
TO0G8qR8P34qrsGXHwSZF8ajrOJP59nSYTRaFm/zucXC950CmwLBMS3+vdU02xGb
AYZJfFOVtiPU4HdB0Z7KX0aTXbtqRJEEF63tjZcJ7M67zT1xAgMBAAGjdzB1MB0G
A1UdDgQWBBSSEwsnoHW75GR+74R+9RJDHlMCJTBGBgNVHSMEPzA9gBSSEwsnoHW7
5GR+74R+9RJDHlMCJaEapBgwFjEUMBIGA1UEAxMLZXhhbXBsZS5jb22CCQD75P7X
i/gc0TAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4GBACJdQamPTI/qf6fo
ovWrffMKnreULYrYAaL4drzQezUpoZ626/Ur3CwpIKqWDsYSvjwKPl0DUyLEuw5J
2QD4X5n/K7/YGGQJSK8fxazsHavyxQhen1uz7X7zWFflIM6+5DvnOtoq3F0yQ84h
L6U2LeRpzO4rWw3kxr/jsGkxYaUR
-----END CERTIFICATE-----
'''

private_key = '''
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDYrIBJjY822hL90KbvGz/FfbrUbDfCcScc1IzUn95O1I+AXwBX
yaSh0HJhXEztBvKkfD9+Kq7Blx8EmRfGo6ziT+fZ0mE0WhZv87nFwvedApsCwTEt
/r3VNNsRmwGGSXxTlbYj1OB3QdGeyl9Gk127akSRBBet7Y2XCezOu809cQIDAQAB
AoGBALU3MORTfOAHa7LUe4mnZKKsEUHwcIIzWN8H9fEu9CNCK/LVgdfqUcL0L3W2
WLA1C2L+d6vxzs8isVKLKBN+eOwUnhbMbMtD8h1SbTUV/JFrZsHycNcff4ythjLW
dMo91+t7EcMKDVmej384Saj8D0z2i1QItvBK/msmSQqdYMXxAkEA72IanU3e5EI1
rkII0/eVLliK6IM+uhaCgAz7Pt7bxntO2NZ8rscn93v6X7SS2Q/QQKyfsT+AbCXk
bMCQE/AsFwJBAOe22JWgT1kIlmPVOaid/XErVV9YYdy7SxkAhvQYzHagWfhQaGpX
sMrX1D5i4eIO9JHRu5zPupCGXRWT43UWr7cCQAi61Smja1t7pqWCNvwz7TbRd89e
6eyzYXL2BjuWuQEWAhwaRlXBYY2+8bSHy0srLncNVI2MOUy4XQoyQ47WlWUCQGZM
vZZhrmZ6ehsdWlVtWyWJoil0FdCkB+XD69D82dhNtysAJPk+Odl0LEpW0a9CNwvh
8tiqhY2lJJeQMU3SdEUCQQCxJ5bXPM5iVDBzV50l3DfDN71srr9KGdCahCuxQpRt
3ZRkZkz9izeRgRM5GRbOM7xpMWKLXFF0E7Y7jF3aa6xD
-----END RSA PRIVATE KEY-----
'''

public_key = '''
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYrIBJjY822hL90KbvGz/FfbrU
bDfCcScc1IzUn95O1I+AXwBXyaSh0HJhXEztBvKkfD9+Kq7Blx8EmRfGo6ziT+fZ
0mE0WhZv87nFwvedApsCwTEt/r3VNNsRmwGGSXxTlbYj1OB3QdGeyl9Gk127akSR
BBet7Y2XCezOu809cQIDAQAB
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
        x5c_certificate = ''.join(certificate.split("\n")[2:-2])
        self.oauth2_v1_keys_response = {
            'keys': [{
                'kid': 'TEST',
                'x5c': [x5c_certificate, 'FAKE', 'FAKE']
                }]
            }
        for domain in ['example.okta.com',
                       'example.oktapreview.com',
                       'invalid.example.com',
                       'invalid.okta.com']:
            responses.add(
                responses.GET,
                'https://{}/.well-known/openid-configuration'.format(domain),
                json.dumps({
                    'jwks_uri': 'https://{}/oauth2/v1/keys'.format(domain)
                }),
                status=200)
            responses.add(
                responses.GET,
                'https://{}/oauth2/v1/keys'.format(domain),
                json.dumps(self.oauth2_v1_keys_response),
                status=200)

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

    @responses.activate
    def test_sso_via_id_token(self):
        id_token = self.create_jwt()
        print id_token
        rv = self.app.post('/sso/oidc', data={'id_token': id_token})
        self.assertIn("Set-Cookie", rv.headers)
        self.assertIn("session=", rv.headers['Set-Cookie'])
        self.assertEquals("302 FOUND", rv.status)
    
    @responses.activate
    def test_sso_via_id_token_invalid(self):
        id_token = self.create_jwt({'aud': 'invalid'})
        print id_token
        rv = self.app.post('/sso/oidc', data={'id_token': id_token})
        self.assertEquals("500 INTERNAL SERVER ERROR", rv.status)

    @responses.activate
    def test_parse_jwt_valid(self):
        id_token = self.create_jwt({})
        rv = flask_app.parse_jwt(id_token)
        self.assertEquals('00u0abcdefGHIJKLMNOP', rv['sub'])

    @responses.activate
    @raises(jwt.InvalidAudienceError)
    def test_parse_jwt_invalid_audience(self):
        id_token = self.create_jwt({'aud': 'INVALID'})
        flask_app.parse_jwt(id_token)

    @responses.activate
    @raises(jwt.InvalidIssuerError)
    def test_parse_jwt_invalid_issuer(self):
        id_token = self.create_jwt({'iss': 'https://invalid.okta.com'})
        flask_app.parse_jwt(id_token)
    
    @responses.activate
    @raises(ValueError)
    def test_parse_jwt_invalid_issuer_domain(self):
        id_token = self.create_jwt({'iss': 'https://invalid.example.com'})
        flask_app.parse_jwt(id_token)
    
    

    @raises(NameError)
    def test_fetch_public_key_for_when_empty(self):
        flask_app.fetch_jwt_public_key_for()

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
