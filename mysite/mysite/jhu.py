from calendar import timegm
import datetime
from jose import jwk, jwt
from jose.jwt import JWTError, JWTClaimsError, ExpiredSignatureError
from jose.utils import base64url_decode
from social_core.backends.oauth import BaseOAuth2
from social_core.exceptions import AuthTokenError

class JHUOAuth2(BaseOAuth2):
    """JHU OAuth authentication backend"""
    name = 'jhu'
    AUTHORIZATION_URL = 'https://slife.jh.edu/VEGAS/oauth/authorize'
    ACCESS_TOKEN_URL = 'https://slife.jh.edu/VEGAS/api/oauth2/token'
    ACCESS_TOKEN_METHOD = 'POST'
    SCOPE_SEPARATOR = ','
    EXTRA_DATA = [
        ('id', 'id'),
        ('expires', 'expires')
    ]
    ID_KEY = 'user_id'
    ID_TOKEN_MAX_AGE = 600
    EXTRA_DATA = [ ('refresh_token', 'refresh_token', True) ]

    def id_token_issuer(self):
        return 'https://slife.jh.edu'

    def validate_claims(self, id_token):
        utc_timestamp = timegm(datetime.datetime.utcnow().utctimetuple())

        if 'nbf' in id_token and utc_timestamp < id_token['nbf']:
            raise AuthTokenError(self, 'Incorrect id_token: nbf')

        # Verify the token was issued in the last 10 minutes
        iat_leeway = self.setting('ID_TOKEN_MAX_AGE', self.ID_TOKEN_MAX_AGE)
        if utc_timestamp > id_token['iat'] + iat_leeway:
            raise AuthTokenError(self, 'Incorrect id_token: iat')


    def validate_and_return_id_token(self, id_token):
        """
        Validates the id_token according to the steps at
        http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation.
        """
        client_id, client_secret = self.get_key_and_secret()

        key = client_secret #self.find_valid_key(id_token)

        if not key:
            raise AuthTokenError(self, 'Signature verification failed')

        #rsakey = jwk.construct(key)

        try:
            claims = jwt.decode(
                id_token,
                key,#rsakey.to_pem().decode('utf-8'),
                audience='UIS Demo', #TODO
                algorithms='HS256',
                issuer=self.id_token_issuer()#,
                #options=self.JWT_DECODE_OPTIONS,
            )
        except ExpiredSignatureError:
            raise AuthTokenError(self, 'Signature has expired')
        except JWTClaimsError as error:
            raise AuthTokenError(self, str(error))
        except JWTError:
            raise AuthTokenError(self, 'Invalid signature')

        self.validate_claims(claims)

        return claims

    def get_user_details(self, response):
        """Return user details from GitHub account"""
        jwt = response.get('access_token')
        user = self.validate_and_return_id_token(jwt)

        #raise Exception('got {}'.format(user))

        return {'username': user.get('sub'),
                'email': user.get('email') or '',
                'first_name': user.get('sub')} ## Todo fname

    def user_data(self, access_token, *args, **kwargs):
         user = self.validate_and_return_id_token(access_token)
         response = {
                'user_id': user['sub'],
                'name': user['sub'],
                'email': user['email']
            }
         return user

    def get_user_id(self, details, response):
        """Use subject (sub) claim as unique id."""
        return response.get('sub')         