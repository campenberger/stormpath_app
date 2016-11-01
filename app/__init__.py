import requests
from flask import Flask
from flask_stormpath import StormpathManager
from stormpath.cache.redis_store import RedisStore

from util import loggingFactory, register_singleton, get_singleton
from views import IndexView, tokenLogin, tokenLogout, TokenTestView


_getLogger=loggingFactory('app.__init__')

def NewApp():
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
register_singleton('stormpathApp',NewApp)
register_singleton('requestsSession', requests.Session)
