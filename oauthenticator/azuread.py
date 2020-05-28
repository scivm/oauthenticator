"""
Custom Authenticator to use Azure AD with JupyterHub
"""

import json
import jwt
import os
import urllib

from tornado.auth import OAuth2Mixin
from tornado.log import app_log
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode, default

from .oauth2 import OAuthLoginHandler, OAuthenticator

#class AzureAdOAuthLoginHandler(OAuthLoginHandler):
#    _state = None
#    def get_state(self):
#        app_log.info("in custom AzureAdOAuthLoginHandler")
#        next_url = original_next_url = self.get_argument('next', None)
#        if next_url:
#            app_log.info("next url exists")
#            app_log.info(next_url)
#            # avoid browsers treating \ as /
#            next_url = next_url.replace('\\', quote('\\'))
#            # disallow hostname-having urls,
#            # force absolute path redirect
#            urlinfo = urlparse(next_url)
#            next_url = urlinfo._replace(
#                scheme='', netloc='', path='/' + urlinfo.path.lstrip('/')
#            ).geturl()
#            if next_url != original_next_url:
#                self.log.warning(
#                    "Ignoring next_url %r, using %r", original_next_url, next_url
#                )
#        if self._state is None:
#            self._state = _serialize_state(
#                {'state_id': uuid.uuid4().hex, 'next_url': next_url}
#            )
#        return self._state

class AzureAdOAuthenticator(OAuthenticator):
#    login_handler = AzureAdOAuthLoginHandler
    login_service = Unicode(
		os.environ.get('LOGIN_SERVICE', 'Azure AD'),
		config=True,
		help="""Azure AD domain name string, e.g. My College"""
	)

    tenant_id = Unicode(config=True, help="The Azure Active Directory Tenant ID")

    @default('tenant_id')
    def _tenant_id_default(self):
        return os.environ.get('AAD_TENANT_ID', '')

    username_claim = Unicode(config=True)

    @default('username_claim')
    def _username_claim_default(self):
        return 'name'

    @default("authorize_url")
    def _authorize_url_default(self):
        return 'https://login.microsoftonline.com/{0}/oauth2/authorize'.format(self.tenant_id)

    @default("token_url")
    def _token_url_default(self):
        return 'https://login.microsoftonline.com/{0}/oauth2/token'.format(self.tenant_id)

    async def authenticate(self, handler, data=None):
        app_log.info("AzureAdOAuthenticator")
        attrs = vars(self)
        for item in attrs.items():
            app_log.info(item)
        app_log.info("checking what is in handler")
        attrs = vars(handler)
        for item in attrs.items():
             app_log.info(item)
        app_log.info(handler.get_argument("state"))
        code = handler.get_argument("code")
        app_log.info(handler.get_argument("code"))
        http_client = AsyncHTTPClient()

        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type='authorization_code',
            code=code,
            state="This is state",
            redirect_uri=self.get_callback_url(handler))

        data = urllib.parse.urlencode(
            params, doseq=True, encoding='utf-8', safe='=')

        url = self.token_url

        headers = {
            'Content-Type':
            'application/x-www-form-urlencoded; charset=UTF-8'
        }
        req = HTTPRequest(
            url,
            method="POST",
            headers=headers,
            body=data  # Body is required for a POST...
        )

        resp = await http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        app_log.info("Response %s", resp_json)
        access_token = resp_json['access_token']

        id_token = resp_json['id_token']
        decoded = jwt.decode(id_token, verify=False)

        userdict = {"name": decoded[self.username_claim]}
        userdict["auth_state"] = auth_state = {}
        auth_state['access_token'] = access_token
        # results in a decoded JWT for the user data
        auth_state['user'] = decoded

        return userdict


class LocalAzureAdOAuthenticator(LocalAuthenticator, AzureAdOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
