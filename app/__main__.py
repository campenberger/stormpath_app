import logging
import copy
import requests
import json
import time
from datetime import datetime
from util import loggingFactory, register_singleton, get_singleton
from flask import Flask, render_template, url_for, redirect,  request, current_app, make_response, flash
from flask_stormpath import StormpathManager, login_required, user
from flask_stormpath.views import login, logout
from flask_stormpath.forms import LoginForm
from flask.views import MethodView
from stormpath.cache.redis_store import RedisStore


_getLogger=loggingFactory('app.__main__')

from stormpath.api_auth import JwtAuthenticator,RefreshGrantAuthenticator,AccessToken,RefreshToken

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

class IndexView(MethodView):

    decorators=(login_required,)
    logger=_getLogger('IndexView')

    def get(self):
        self.logger.debug("User: {}".format(user))
        client=get_singleton('stormpathApp').client

        current_org=request.values.get('current_org',-1)
        for o in user.directory.organizations.items:
            if o['nameKey']==current_org:
                current_org=o
                break
        else:
            current_org=user.directory.organizations.items[0]
        current_org=client.organizations.get(current_org['href'])

        # get account permissions
        try:
            permissions=copy.copy(user.custom_data['permissions'])
        except KeyError:
            permissions=[]

        # add group permissions
        for g in user.groups.items:
            logger.debug('Got group %s for user %s',g.name,user.email)
            try:
                permissions+=g.custom_data['permissions']
            except KeyError:
                logger.debug('   * has no permissions')

        # retreive the org's custom data
        try:
            app_custom_data=current_org.custom_data
        except KeyError:
            logger.exception('Unable to find customData href')
            app_custom_data={}
            
        tc=TokenCookie()
        tc.load()

        context={
            'user': user,
            'logout_url': url_for('stormpath.logout'),
            'index_url': url_for('index'),
            'token_test_url': url_for('token_test'),
            'organizations': user.directory.organizations.items,
            'current_org': current_org,
            'current_org_nameKey': current_org.name_key,
            'permissions': sorted(permissions),
            'token': json.dumps(tc.value,indent=2)
        }
        return render_template('index.html',**context)

    def post(self):
        self.logger.debug("Form submitted")
        return redirect(url_for('index',current_org=request.values.get('tenant_select',-1)))



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
            logger.debug("Expiration: %s",str(datetime.fromtimestamp(access_token.exp)))

            token_cookie.value['access_token']=access_token.token
            token_cookie.modified=True
            
            return access_token

        else:
            self.logger.info("Unable to refresh token")
            return None

            

def tokenLogin():
    ''' Extended login view to also obtain a JWT token that can be used
        by the app
    '''
    logger=_getLogger('tokenLogin')
    ret=login()
    if not isinstance(ret,unicode) and ret.status_code==302:
        logger.debug("Response status is 302 - so a successful login occured")
        
        form=LoginForm()
        logger.debug("Try to get token for {} /{}".format(form.login.data, '*'*len(form.password.data)))
        tm=TokenManager()
        if not tm.issue(form.login.data, form.password.data, ret):
            flash("Unable to obtain oauth token - logged out!")
            return render_template(
                current_app.config['STORMPATH_LOGIN_TEMPLATE'],
                form = form,
            )

    return ret

def tokenLogout():
    logger=_getLogger('tokenLogout')
    ret=logout()
    if isinstance(ret,basestring):
        ret=make_response()
    TokenCookie().delete(ret)
    return ret



def _authenticate(f):
    def wrapped(*args,**kwargs):
        logger=_getLogger('_authenticate')
        tc=TokenCookie()
        tc.load()
        token=TokenManager().authenticate(tc)
        if token is None:
            logger.info("Unable to refresh token")
            flash("Unable to authenticate throuh token")
            return current_app.login_manager.unauthorized()

        else:
            kwargs['token']=token
            ret=f(*args,**kwargs)
            if isinstance(ret,basestring):
                ret=make_response(ret)
            tc.save(ret)
            return ret

    return wrapped

class TokenTestView(MethodView):

    logger=_getLogger('TokenTestView')

    def get(self,token=None):
        context={
            'token': token,
            'current_time': datetime.now(),
            'expiration_time': datetime.fromtimestamp(token.exp),
            'logout_url': url_for('stormpath.logout'),
            'index_url': url_for('index')
        }
        return render_template('token_test.html',**context)

    decorators=[_authenticate]

def _NewApp():
    cfg=get_singleton('config')
    settings={
        'SECRET_KEY': '4jxu347ciKeMbRJBHQefmxwR',
        'STORMPATH_API_KEY_ID': cfg.get('stormpath','api_key_id'),
        'STORMPATH_API_KEY_SECRET': cfg.get('stormpath', 'api_key_secret'),
        'STORMPATH_APPLICATION': 'Fusion',
        'STORMPATH_ENABLE_REGISTRATION': False,
        'STORMPATH_ENABLE_FORGOT_PASSWORD': True,
        'STORMPATH_CACHE': { 
            'store': RedisStore, 
            'ttl': 300,
            'store_opts': { 'host': 'localhost', 'port': 6379 }
        },

        # we disable login, so we can register our own version of it
        'STORMPATH_ENABLE_LOGIN': False,
        'STORMPATH_ENABLE_LOGOUT': False,

        'DEBUG': True
    }
    app=Flask(__name__)
    app.config.update(settings)
    app.add_url_rule('/',view_func=IndexView.as_view('index'))
    app.add_url_rule('/token_test',view_func=TokenTestView.as_view('token_test'))

    sm=StormpathManager(app)

    # register the login
    app.config['STORMPATH_ENABLE_LOGIN']=True
    app.add_url_rule(
        app.config['STORMPATH_LOGIN_URL'],
        'stormpath.login',
        tokenLogin,
        methods = ['GET', 'POST'],
    )
    app.add_url_rule(
        app.config['STORMPATH_LOGOUT_URL'],
        'stormpath.logout',
        tokenLogout,
    )
    app.login_manager.login_view = 'stormpath.login'

    return sm


def Config():
    ''' Reads ./config.ini with ConfigParser and returns
        the ConfigParser object
    '''
    from ConfigParser import ConfigParser
    cfg=ConfigParser()
    with open('config.ini','r') as fh:
        cfg.readfp(fh)
    return cfg

register_singleton('config',Config)
register_singleton('stormpathApp',_NewApp)
register_singleton('requestsSession', requests.Session)

# todo: add read me
# move code into __init__.py
# todo: push to github

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(name)-15s %(message)s')
    logger=_getLogger()

    logger.debug("starting the server")
    get_singleton('stormpathApp').app.run(threaded=True)
