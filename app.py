import json
import os
import re
import urllib
import urlparse

from flask import Flask
from flask import flash
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from flask_login import LoginManager
from flask_login import current_user
from flask_login import login_required
from flask_login import login_user
from flask_login import logout_user
from jose import jws
from jose import jwt
import flask
import requests


not_alpha_numeric = re.compile('[^a-zA-Z0-9]+')

required = {
    'base_url': {
        'description': 'the base URL for your Okta org',
        'example': 'https://example.okta.com'
    },
    'api_token': {
        'description': 'the API token for your Okta org',
        'example': '01A2bCd3efGh-ij-4K-Lmn5OPqrSTuvwXYZaBCD6EF'
    },
    'client_id': {
        'description': 'an OAuth Client ID for your Okta org',
        'example': 'a0bcdEfGhIJkLmNOPQr1'
    }
}

okta = {}
for key in required.keys():
    env_key = "OKTA_" + key.upper()
    okta[key] = os.environ.get(env_key)
    if okta[key]:
        del(required[key])

headers = {
    # "Authorization" is only needed for social transaction calls
    'Authorization': 'SSWS {}'.format(okta['api_token']),
    'Content-Type': 'application/json',
    'Accept': 'application/json',
}

app = Flask(__name__)

public_keys = {}
allowed_domains = ['okta.com', 'oktapreview.com']
# The 'app.secret_key' variable is used by flask-login
# to hash the cookies that it gives to logged in users.
# Since the Okta API token must be kept secret, we will reuse it here.
# You should set this to your own secret value in a production environment!
app.secret_key = okta['api_token']

login_manager = LoginManager()
login_manager.setup_app(app)


class UserSession:
    def __init__(self, user_id):
        self.authenticated = True
        self.user_id = user_id

    def is_active(self):
        # In this example, "active" and "authenticated" are the same thing
        return self.authenticated

    def is_authenticated(self):
        # "Has the user authenticated?"
        # See also: http://stackoverflow.com/a/19533025
        return self.authenticated

    def is_anonymous(self):
        return not self.authenticated

    def get_id(self):
        return self.user_id


# Note that this loads users based on user_id
# which is stored in the browser cookie, I think
@login_manager.user_loader
def load_user(user_id):
    # print "Loading user: " + user_id
    return UserSession(user_id)


def domain_name_for(url):
    second_to_last_element = -2
    domain_parts = url.netloc.split('.')
    (sld, tld) = domain_parts[second_to_last_element:]
    return sld + '.' + tld


# FIXME: Rename since this is not about public keys anymore
def fetch_jwt_public_key_for(id_token=None):
    if id_token is None:
        raise NameError('id_token is required')

    dirty_header = jws.get_unverified_header(id_token)
    cleaned_key_id = None
    if 'kid' in dirty_header:
        dirty_key_id = dirty_header['kid']
        cleaned_key_id = re.sub(not_alpha_numeric, '', dirty_key_id)
    else:
        raise ValueError('The id_token header must contain a "kid"')
    if cleaned_key_id in public_keys:
        return public_keys[cleaned_key_id]

    unverified_claims = jwt.get_unverified_claims(id_token)
    dirty_url = urlparse.urlparse(unverified_claims['iss'])
    if domain_name_for(dirty_url) not in allowed_domains:
        raise ValueError('The domain in the issuer claim is not allowed')
    cleaned_issuer = dirty_url.geturl()
    oidc_discovery_url = "{}/.well-known/openid-configuration".format(
        cleaned_issuer)
    r = requests.get(oidc_discovery_url)
    openid_configuration = r.json()
    jwks_uri = openid_configuration['jwks_uri']
    r = requests.get(jwks_uri)
    jwks = r.json()
    for key in jwks['keys']:
        jwk_id = key['kid']
        public_keys[jwk_id] = key

    if cleaned_key_id in public_keys:
        return public_keys[cleaned_key_id]
    else:
        raise RuntimeError("Unable to fetch public key from jwks_uri")


@app.route("/spa")
def spa():
    return render_template(
        'spa.html',
        okta=okta)


@app.route("/secret")
@login_required
def logged_in():
    opts = {'user': current_user}
    return render_template(
        'secret.html',
        opts=opts,
        okta=okta)


def parse_jwt(id_token):
    public_key = fetch_jwt_public_key_for(id_token)
    rv = jwt.decode(
        id_token,
        public_key,
        algorithms='RS256',
        issuer=okta['base_url'],
        audience=okta['client_id'])
    return rv


def create_authorize_url(**kwargs):
    base_url = kwargs['base_url']
    del(kwargs['base_url'])
    redirect_url = "{}/oauth2/v1/authorize?{}".format(
        base_url,
        urllib.urlencode(kwargs),
    )
    return redirect_url


@app.route("/login", methods=['POST'])
def login_with_password():
    payload = {
        'username': request.form['username'],
        'password': request.form['password'],
        }

    authn_url = "{}/api/v1/authn".format(okta['base_url'])
    r = requests.post(authn_url, headers=headers, data=json.dumps(payload))
    result = r.json()

    if 'errorCode' in result:
        flash(result['errorSummary'])
        return redirect(url_for('main_page', _external=True, _scheme='https'))

    redirect_uri = url_for(
        'sso_oidc',
        _external=True,
        _scheme='https')
    redirect_url = create_authorize_url(
        base_url=okta['base_url'],
        sessionToken=result['sessionToken'],
        client_id=okta['client_id'],
        scope='openid',
        response_type='id_token',
        response_mode='form_post',
        nonce='FakeNonce',
        state='FakeState',
        redirect_uri=redirect_uri,
        )
    return redirect(redirect_url)


@app.route("/sso/oidc", methods=['GET', 'POST'])
def sso_oidc():
    if 'error' in request.form:
        flash(request.form['error_description'])
        return redirect(url_for('main_page', _external=True, _scheme='https'))
    id_token = request.form['id_token']
    decoded = parse_jwt(id_token)
    user_id = decoded['sub']
    user = UserSession(user_id)
    login_user(user)
    return redirect(url_for('logged_in', _external=True, _scheme='https'))


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('main_page', _external=True, _scheme='https'))


# FIXME: Use decoded['sub'] to fetch the user profile from Okta,
# returning that in the result
@app.route("/users/me")
def users_me():
    authorization = request.headers.get('Authorization')
    token = authorization.replace('Bearer ', '')
    decoded = parse_jwt(token)
    rv = {'user_id': decoded['sub']}
    return flask.jsonify(**rv)


@app.route("/")
def main_page():
    if len(required.keys()) > 0:
        return render_template(
            'error.html',
            required=required,
            okta=okta)
    redirect_uri = url_for(
        'sso_oidc',
        _external=True,
        _scheme='https')
    login_with_okta_branding = create_authorize_url(
        base_url=okta['base_url'],
        client_id=okta['client_id'],
        scope='openid',
        response_type='id_token',
        response_mode='form_post',
        nonce='FakeNonce',
        state='FakeState',
        redirect_uri=redirect_uri)
    target_origin = url_for('main_page', _external=True, _scheme='https')
    return render_template(
        'main_page.html',
        target_origin=target_origin,
        login_with_okta_branding=login_with_okta_branding,
        okta=okta)


if __name__ == "__main__":
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    if port == 5000:
        app.debug = True
    app.run("0.0.0.0", port=port)
