import logging

import tornado.gen
import tornado.web

from webssh.handler import (
    ACCOUNT_URL, ADMIN_USERS_URL, SIGNIN_URL, MixinHandler,
    SignInRequiredMixin, password_executor
)
from webssh.signin import (
    Session, check_password, hash_password, password_error, username_error
)


NAME_FIELDS = ('firstname', 'lastname', 'middlename')


class AdministratorRequiredMixin(SignInRequiredMixin):
    """Lets only a signed-in Administrator through."""

    forbidden_message = 'Only administrators can manage users'

    def prepare(self):
        super(AdministratorRequiredMixin, self).prepare()
        if self._finished:
            return
        if not self.signed_in_user.is_admin:
            self.set_status(403)
            self.render('forbidden.html', message=self.forbidden_message)

    def log_action(self, action, username):
        logging.info('Administrator {!r} {} {!r}'.format(
            self.signed_in_user.username, action, username))


class UsersHandler(AdministratorRequiredMixin, MixinHandler,
                   tornado.web.RequestHandler):

    def get(self):
        self.render_page()

    def render_page(self, error=None, form=None):
        self.render('admin_users.html', error=error, form=form or {},
                    users=self.settings['user_store'].list())

    @tornado.gen.coroutine
    def post(self):
        store = self.settings['user_store']
        form = {name: self.get_argument(name, u'')
                for name in ('username',) + NAME_FIELDS}
        form['is_admin'] = bool(self.get_argument('is_admin', u''))
        password = self.get_raw_argument('password')

        error = username_error(form['username']) or \
            password_error(password, self.get_raw_argument('password2'))
        if not error and store.is_username_taken(form['username']):
            error = 'Username is taken'
        if error:
            self.render_page(error, form)
            return

        password_hash = yield password_executor.submit(hash_password,
                                                       password)
        store.create(form['username'], password_hash, form['is_admin'],
                     *(form[name] for name in NAME_FIELDS))
        self.log_action('created user', form['username'])
        self.redirect(ADMIN_USERS_URL, status=303)


class UserHandler(AdministratorRequiredMixin, MixinHandler,
                  tornado.web.RequestHandler):
    """One User's page and the actions on that User."""

    def find_user(self, user_id):
        user = self.settings['user_store'].find_by_id(int(user_id))
        if not user:
            raise tornado.web.HTTPError(404)
        return user

    def get(self, user_id):
        self.render_page(self.find_user(user_id))

    def render_page(self, user, error=None):
        self.render('admin_user.html', user=user, error=error,
                    page_url=self.request.path)

    @tornado.gen.coroutine
    def post(self, user_id):
        user = self.find_user(user_id)
        store = self.settings['user_store']
        action = self.get_argument('action', u'')
        if action == 'names':
            store.update_names(user.id, *(self.get_argument(name, u'')
                                          for name in NAME_FIELDS))
            self.log_action('changed the name of', user.username)
        elif action == 'password':
            password = self.get_raw_argument('password')
            error = password_error(password,
                                   self.get_raw_argument('password2'))
            if error:
                self.render_page(user, error)
                return
            password_hash = yield password_executor.submit(hash_password,
                                                           password)
            store.set_password(user.id, password_hash)
            self.log_action('set the password of', user.username)
        elif action in self.flag_actions:
            # the acting Administrator is always active and an
            # Administrator, so refusing these on oneself also keeps at
            # least one active Administrator
            refusal, setter, value, log = self.flag_actions[action]
            if refusal and user.id == self.signed_in_user.id:
                self.render_page(user, refusal)
                return
            getattr(store, setter)(user.id, value)
            self.log_action(log, user.username)
        else:
            raise tornado.web.HTTPError(400, 'Unknown action')
        self.redirect(self.request.path, status=303)

    # action: (refusal when done to oneself, store method, value, log text)
    flag_actions = {
        'deactivate': ('You can not deactivate yourself', 'set_active',
                       False, 'deactivated'),
        'activate': (None, 'set_active', True, 'reactivated'),
        'grant': (None, 'set_admin', True, 'granted administration to'),
        'revoke': ('You can not revoke your own administration',
                   'set_admin', False, 'revoked administration from'),
    }


class AccountHandler(SignInRequiredMixin, MixinHandler,
                     tornado.web.RequestHandler):
    """The signed-in User's own password and sessions."""

    def get(self):
        self.render('account.html', error=None)

    @tornado.gen.coroutine
    def post(self):
        user = self.signed_in_user
        store = self.settings['user_store']
        action = self.get_argument('action', u'')

        if action == 'signout_everywhere':
            store.end_sessions(user.id)
            self.clear_cookie(self.session_cookie)
            logging.info('User {!r} signed out everywhere'.format(
                user.username))
            self.redirect(SIGNIN_URL, status=303)
            return
        if action != 'password':
            raise tornado.web.HTTPError(400, 'Unknown action')

        password = self.get_raw_argument('password')
        matched = yield password_executor.submit(
            check_password, user, self.get_raw_argument('current')
        )
        error = None if matched else 'Current password is wrong'
        error = error or password_error(password,
                                        self.get_raw_argument('password2'))
        if error:
            self.render('account.html', error=error)
            return

        password_hash = yield password_executor.submit(hash_password,
                                                       password)
        store.set_password(user.id, password_hash)
        # the other sessions end, this browser stays signed in
        self.save_session(Session.for_user(store.find_by_id(user.id)))
        logging.info('User {!r} changed their password'.format(
            user.username))
        self.redirect(ACCOUNT_URL, status=303)
