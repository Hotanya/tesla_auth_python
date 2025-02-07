#!/usr/bin/python3

# Python implementation of the awesome work done by Adrian at https://github.com/adriankumpf/tesla_auth

import time
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs
import secrets
import hashlib
import base64

from oauthlib.oauth2 import WebApplicationClient
from requests_oauthlib import OAuth2Session

CLIENT_ID = 'YOURCLIENTID' #register an app at https://developer.tesla.com/
AUTH_URL = 'https://auth.tesla.com/oauth2/v3/authorize'
TOKEN_URL = 'https://auth.tesla.com/oauth2/v3/token'
TOKEN_URL_CN = 'https://auth.tesla.cn/oauth2/v3/token'
REDIRECT_URL = 'https://auth.tesla.com/void/callback'

def is_redirect_url(url: str) -> bool:
    return url.startswith(REDIRECT_URL)

def generate_pkce_pair():
    # Generate a high-entropy code verifier
    code_verifier = secrets.token_urlsafe(64)
    # Create a code challenge derived from the code verifier
    code_challenge = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).rstrip(b'=').decode('ascii')
    return code_verifier, code_challenge

@dataclass
class Tokens:
    access: str
    refresh: str
    expires_in: int

    def __str__(self):
        return f'''
--------------------------------- ACCESS TOKEN ---------------------------------

{self.access}

--------------------------------- REFRESH TOKEN --------------------------------

{self.refresh}

----------------------------------- VALID FOR ----------------------------------

{self.expires_in} seconds
        '''

class Client:
    def __init__(self):
        self.code_verifier, self.code_challenge = generate_pkce_pair()
        self.csrf_token = secrets.token_urlsafe(32)
        self.oauth_client = OAuth2Session(
            client=WebApplicationClient(client_id=CLIENT_ID),
            redirect_uri=REDIRECT_URL,
            scope=['openid', 'email', 'offline_access', 'user_data', 'vehicle_device_data', 'vehicle_cmds', 'vehicle_charging_cmds'], #all the read scopes, no writing to the car
        )
        # Generate the authorization URL
        self.auth_url, self.state = self.oauth_client.authorization_url(
            AUTH_URL,
            code_challenge=self.code_challenge,
            code_challenge_method='S256',
            state=self.csrf_token,
        )
        print(f'Generated PKCE Code Verifier: {self.code_verifier}')
        print(f'Generated PKCE Code Challenge: {self.code_challenge}')
        print(f'Generated CSRF Token: {self.csrf_token}')
        print(f'Authorization URL: {self.auth_url}')
        # For Chinese users
        self.oauth_client_cn = OAuth2Session(
            client=WebApplicationClient(client_id=CLIENT_ID),
            redirect_uri=REDIRECT_URL,
            scope=['openid', 'email', 'offline_access'],
        )

    def authorize_url(self) -> str:
        return self.auth_url

    def retrieve_tokens(self, code: str, state: str, issuer: str) -> Tokens:
        if state != self.csrf_token:
            raise ValueError("CSRF state does not match!")

        parsed_issuer = urlparse(issuer)
        if parsed_issuer.hostname == 'auth.tesla.cn':
            token_url = TOKEN_URL_CN
            client = self.oauth_client_cn
            print('Using Chinese token URL.')
        else:
            token_url = TOKEN_URL
            client = self.oauth_client
            print('Using global token URL.')

        print(f'Fetching tokens from: {token_url}')
        token = client.fetch_token(
            token_url=token_url,
            code=code,
            client_id=CLIENT_ID,
            code_verifier=self.code_verifier,
            include_client_id=True,
        )

        tokens = Tokens(
            access=token.get('access_token'),
            refresh=token.get('refresh_token'),
            expires_in=token.get('expires_in'),
        )
        print('Tokens retrieved successfully!')
        return tokens

# Sample usage
if __name__ == '__main__':
    client = Client()
    print('\nPlease go to the following URL to authorize the application:')
    print(client.authorize_url())

    # Simulate user completing authorization and being redirected with code and state
    redirect_response = input('\nAfter authorization, please paste the full redirect URL here:\n')

    # Parse the redirect response to extract code and state
    parsed_url = urlparse(redirect_response)
    query_params = parse_qs(parsed_url.query)
    code = query_params.get('code', [None])[0]
    state = query_params.get('state', [None])[0]

    if code and state:
        issuer = f'{parsed_url.scheme}://{parsed_url.netloc}'
        print(f'\nAuthorization code: {code}')
        print(f'CSRF state: {state}')
        print(f'Issuer URL: {issuer}')
        tokens = client.retrieve_tokens(code, state, issuer)
        print(tokens)
    else:
        print('Error: Authorization code or state parameter is missing.')
