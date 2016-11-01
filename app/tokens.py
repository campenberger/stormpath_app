import json
from datetime import datetime
from util import loggingFactory
from flask import request, current_app
from util import loggingFactory, get_singleton

from stormpath.api_auth import JwtAuthenticator,RefreshGrantAuthenticator,AccessToken,RefreshToken

_getLogger=loggingFactory('app.tokens')


class TokenCookie(object):

    cookie_name="lexsol_token"
    logger=_getLogger('TokenCookie')
    _value=None

    def load(self):
        self._value=request.cookies.get(TokenCookie.cookie_name, None)
        if self._value:
            self._value=json.loads(self._value)
        self.modified=False
        self.logger.debug('Cookie from request: %s',self._value)

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self,value):
        self._value=value
        self.modified=True
        self.logger.debug("Value has been updated: %s",value)

    def save(self,response):
        if self.modified:
            sm=get_singleton('stormpathApp')
            rt=RefreshToken(sm.application, self._value['refresh_token'])
            self.logger.debug("Refresh token: {}".format(rt.to_json()))
            response.set_cookie(self.cookie_name,json.dumps(self._value),expires=rt.exp)

    def delete(self,response):
        response.set_cookie(self.cookie_name,'',expires=0)


class TokenManager(object):

    logger=_getLogger('TokenManager')

    def issue(self,username,password,response):
        sm=get_singleton('stormpathApp')
        r_session=get_singleton('requestsSession')

        uri = sm.application.href + '/oauth/token'
        payload = {
            'grant_type': 'password',
            'username': username,
            'password': password
        }
        
        result = r_session.post(
            uri,
            data=payload,
            auth=(current_app.config['STORMPATH_API_KEY_ID'], current_app.config['STORMPATH_API_KEY_SECRET'])
        )
        if result.status_code!=200:
            logger.error("Error getting oauth token (%d): %s",result.status_code,result.json())
            return False
        else:
            tc=TokenCookie()
            tc.value=result.json()
            tc.save(response)

            return True

    def authenticate(self,token_cookie):
        sm=get_singleton('stormpathApp')
        authenticator=JwtAuthenticator(sm.application)
        if token_cookie.value:
            self.logger.debug('Trying local authentication of token: %s',token_cookie.value['access_token'])
            token=authenticator.authenticate(token_cookie.value['access_token'],local_validation=True,expand=True)
            if token is None:
                self.logger.info("Unable to authenticate token - trying refresh")
                token=self._refresh(token_cookie)
            return token
        else:
            return None

    def _refresh(self,token_cookie):
        sm=get_singleton('stormpathApp')
        authenticator=RefreshGrantAuthenticator(sm.application)
        pwResult=authenticator.authenticate(token_cookie.value['refresh_token'])
        if pwResult is not None:
            access_token=pwResult.access_token
            self.logger.debug("Successful refresh: {}".format(access_token.token))
            self.logger.debug("Expiration: %s",str(datetime.fromtimestamp(access_token.exp)))

            token_cookie.value['access_token']=access_token.token
            token_cookie.modified=True
            
            return access_token

        else:
            self.logger.info("Unable to refresh token")
            return None
