import copy
import json
from datetime import datetime
from flask import request, render_template, url_for, redirect
from flask.views import MethodView
from flask_stormpath import user, login_required
from flask_stormpath.forms import LoginForm
from flask_stormpath.views import login, logout
from util import loggingFactory, get_singleton
from tokens import TokenCookie, TokenManager
from decorators import _authenticated

_getLogger=loggingFactory('app.views')

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
            self.logger.debug('Got group %s for user %s',g.name,user.email)
            try:
                permissions+=g.custom_data['permissions']
            except KeyError:
                logger.debug('   * has no permissions')

        # retreive the org's custom data
        try:
            app_custom_data=current_org.custom_data
        except KeyError:
            self.logger.exception('Unable to find customData href')
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

    decorators=[_authenticated]
