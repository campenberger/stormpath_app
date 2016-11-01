from util import loggingFactory, get_singleton
from tokens import TokenCookie, TokenManager
from flask import flash, current_app, make_response

_getLogger=loggingFactory('app.decorators')

def _authenticated(f):
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