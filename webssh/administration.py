import logging

import tornado.gen
import tornado.web

from webssh.handler import MixinHandler, SignInRequiredMixin
from webssh.signin import (
    LastAdministrator, Names, Session, UsernameTaken,
    check_password_off_loop, hash_password_off_loop, password_error,
    username_error
)
from webssh.urls import PROFILE_URL, SIGNIN_URL, USERS_URL


LAST_ADMINISTRATOR = 'At least one active Administrator must remain'


class FormMixin(SignInRequiredMixin):
    """Reading the user forms, and posting to one of several actions."""

    actions = {}

    def read_names(self):
        return Names(*(self.get_argument(field, u'')
                       for field in Names.fields))

    def read_new_password(self):
        """Returns the new password typed twice, and what is wrong with it."""
        password = self.get_raw_argument('password')
        return password, password_error(password,
                                        self.get_raw_argument('password2'))

    @tornado.gen.coroutine
    def run_action(self, *args):
        """Runs the posted action: it returns an error to show, or None."""
        action = self.actions.get(self.get_argument('action', u''))
        if not action:
            raise tornado.web.HTTPError(400, 'Unknown action')
        error = yield tornado.gen.maybe_future(action(self, *args))
        return error


class AdministratorRequiredMixin(FormMixin):
    """Lets only a signed-in Administrator through."""

    forbidden_message = 'Only administrators can manage users'

    def prepare(self):
        super(AdministratorRequiredMixin, self).prepare()
        if self._finished:
            return
        if not self.signed_in_user.is_administrator:
            self.set_status(403)
            self.render('forbidden.html', message=self.forbidden_message)

    def log_action(self, action, user):
        logging.info('Administrator {!r} {} {!r}'.format(
            self.signed_in_user.username, action, user.username))


class UsersHandler(AdministratorRequiredMixin, MixinHandler,
                   tornado.web.RequestHandler):

    def get(self):
        self.render_page()

    def render_page(self, error=None, username=u'', names=None,
                    is_administrator=False):
        self.render('users.html', error=error, username=username,
                    names=names or Names(), is_administrator=is_administrator,
                    users=self.settings['user_store'].list())

    @tornado.gen.coroutine
    def post(self):
        store = self.settings['user_store']
        username = self.get_argument('username', u'')
        names = self.read_names()
        is_administrator = bool(self.get_argument('is_administrator', u''))
        password, error = self.read_new_password()

        error = username_error(username) or error
        if not error and store.is_username_taken(username):
            error = 'Username is taken'
        if not error:
            password_hash = yield hash_password_off_loop(password)
            try:
                store.create(username, password_hash, is_administrator,
                             names)
            except UsernameTaken:
                # created by a concurrent request while hashing
                error = 'Username is taken'
        if error:
            self.render_page(error, username, names, is_administrator)
            return

        logging.info('Administrator {!r} created user {!r}'.format(
            self.signed_in_user.username, username))
        self.redirect(USERS_URL, status=303)


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
        self.render('user.html', user=user, error=error,
                    page_url=self.request.path,
                    is_self=user.id == self.signed_in_user.id)

    @tornado.gen.coroutine
    def post(self, user_id):
        user = self.find_user(user_id)
        error = yield self.run_action(user)
        if error:
            self.render_page(user, error)
            return
        self.redirect(self.request.path, status=303)

    def change_names(self, user):
        self.settings['user_store'].update_names(user.id, self.read_names())
        self.log_action('changed the name of', user)

    @tornado.gen.coroutine
    def set_password(self, user):
        if user.id == self.signed_in_user.id:
            # here it would skip the current password and sign them out
            return 'Change your own password in My profile'
        password, error = self.read_new_password()
        if error:
            return error
        password_hash = yield hash_password_off_loop(password)
        self.settings['user_store'].set_password(user.id, password_hash)
        self.log_action('set the password of', user)

    def deactivate(self, user):
        if user.id == self.signed_in_user.id:
            return 'You can not deactivate yourself'
        try:
            self.settings['user_store'].set_active(user.id, False)
        except LastAdministrator:
            return LAST_ADMINISTRATOR
        self.log_action('deactivated', user)

    def reactivate(self, user):
        self.settings['user_store'].set_active(user.id, True)
        self.log_action('reactivated', user)

    def grant(self, user):
        self.settings['user_store'].set_administrator(user.id, True)
        self.log_action('granted administration to', user)

    def revoke(self, user):
        if user.id == self.signed_in_user.id:
            return 'You can not revoke your own administration'
        try:
            self.settings['user_store'].set_administrator(user.id, False)
        except LastAdministrator:
            return LAST_ADMINISTRATOR
        self.log_action('revoked administration from', user)

    actions = {
        'names': change_names,
        'password': set_password,
        'deactivate': deactivate,
        'activate': reactivate,
        'grant': grant,
        'revoke': revoke,
    }


class ProfileHandler(FormMixin, MixinHandler, tornado.web.RequestHandler):
    """The signed-in User's own password and sessions."""

    def get(self):
        self.render('profile.html', error=None)

    @tornado.gen.coroutine
    def post(self):
        error = yield self.run_action()
        if error:
            self.render('profile.html', error=error)
        elif not self._finished:
            self.redirect(PROFILE_URL, status=303)

    @tornado.gen.coroutine
    def change_password(self):
        user = self.signed_in_user
        store = self.settings['user_store']
        matched = yield check_password_off_loop(
            user, self.get_raw_argument('current'))
        if not matched:
            return 'Current password is wrong'
        password, error = self.read_new_password()
        if error:
            return error

        password_hash = yield hash_password_off_loop(password)
        store.set_password(user.id, password_hash)
        # the other sessions end, this browser stays signed in
        self.save_session(Session.for_user(store.find_by_id(user.id)))
        logging.info('User {!r} changed their password'.format(
            user.username))

    def sign_out_everywhere(self):
        self.settings['user_store'].end_sessions(self.signed_in_user.id)
        self.clear_cookie(self.session_cookie)
        logging.info('User {!r} signed out everywhere'.format(
            self.signed_in_user.username))
        self.redirect(SIGNIN_URL, status=303)

    actions = {
        'password': change_password,
        'signout_everywhere': sign_out_everywhere,
    }
