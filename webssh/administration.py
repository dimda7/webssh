import logging

import tornado.gen
import tornado.web

from webssh.handler import (
    DEFAULT_PORT, InvalidValueError, MixinHandler, PrivateKey,
    SignInRequiredMixin
)
from webssh.saved_hosts import NameTaken, SavedHostGone
from webssh.signin import (
    LastAdministrator, Names, Session, TooManyAttempts, UserGone,
    UsernameTaken, check_password_limited, hash_password_off_loop,
    password_error, username_error
)
from webssh.urls import PROFILE_URL, SAVED_HOSTS_URL, SIGNIN_URL, USERS_URL
from webssh.utils import (
    is_valid_hostname, is_valid_ip_address, is_valid_port, to_int
)


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
        try:
            error = yield self.run_action(user)
        except UserGone:
            raise tornado.web.HTTPError(404)
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
        # whoever guesses here is already signed in as this User, so the
        # attempts count per User, apart from sign-in's per-IP count
        try:
            matched = yield check_password_limited(
                self.settings['profile_limiter'], user.id, user.username,
                user, self.get_raw_argument('current')
            )
        except TooManyAttempts:
            return 'Too many attempts, try later'
        if not matched:
            return 'Current password is wrong'
        password, error = self.read_new_password()
        if error:
            return error

        password_hash = yield hash_password_off_loop(password)
        try:
            store.set_password(user.id, password_hash)
        except UserGone:
            # removed from the DB while bcrypt ran
            self.clear_cookie(self.session_cookie)
            self.redirect(SIGNIN_URL, status=303)
            return
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


class SavedHostsHandler(FormMixin, MixinHandler, tornado.web.RequestHandler):
    """The signed-in User's own Saved Hosts."""

    def get(self):
        self.render('saved_hosts.html', saved_hosts=self.settings[
            'user_store'].saved_hosts.list(self.signed_in_user.id))


class SavedHostHandler(FormMixin, MixinHandler, tornado.web.RequestHandler):
    """One of the signed-in User's Saved Hosts and the actions on it.

    Its secret can be replaced here but is never shown.
    """

    name_taken = 'You already have a saved host with this name'

    @property
    def store(self):
        return self.settings['user_store'].saved_hosts

    def find_host(self, host_id):
        try:
            return self.store.find(self.signed_in_user.id, int(host_id))
        except SavedHostGone:
            # someone else's Saved Host looks the same as a missing one
            raise tornado.web.HTTPError(404)

    def get(self, host_id):
        self.render_page(self.find_host(host_id))

    def render_page(self, host, error=None):
        self.render('saved_host.html', host=host, error=error,
                    page_url=self.request.path)

    @tornado.gen.coroutine
    def post(self, host_id):
        host = self.find_host(host_id)
        try:
            error = yield self.run_action(host)
        except SavedHostGone:
            raise tornado.web.HTTPError(404)
        if error:
            self.render_page(host, error)
        elif not self._finished:
            self.redirect(self.request.path, status=303)

    def log_action(self, action, host):
        logging.info('User {!r} {} saved host {!r}'.format(
            self.signed_in_user.username, action, host.name))

    def change_details(self, host):
        name = self.get_argument('name', u'')
        hostname = self.get_argument('hostname', u'')
        port_value = self.get_argument('port', u'')
        port = to_int(port_value) if port_value else DEFAULT_PORT
        username = self.get_argument('username', u'')
        if not name:
            return 'Name is required'
        if not (is_valid_hostname(hostname) or
                is_valid_ip_address(hostname)):
            return 'Invalid hostname: {}'.format(hostname)
        if port is None or not is_valid_port(port):
            return 'Invalid port: {}'.format(port_value)
        if not username:
            return 'Username is required'
        try:
            self.store.update_details(self.signed_in_user.id, host.id, name,
                                      hostname, port, username)
        except NameTaken:
            return self.name_taken
        self.log_action('changed', host)

    def set_password(self, host):
        # taken verbatim: it goes to the remote host as typed
        password = self.get_raw_argument('password')
        if not password:
            return 'Password is required'
        self.store.set_password(self.signed_in_user.id, host.id, password)
        self.log_action('set the password of', host)

    def set_key(self, host):
        files = self.request.files.get('privatekey')
        if not files:
            return 'Choose a private key file'
        privatekey = self.decode_argument(files[0]['body'],
                                          name='privatekey').strip()
        passphrase = self.get_raw_argument('passphrase') or None
        try:
            PrivateKey(privatekey, passphrase).get_pkey_obj()
        except InvalidValueError:
            return 'Invalid private key or wrong passphrase'
        self.store.set_key(self.signed_in_user.id, host.id, privatekey,
                           passphrase)
        self.log_action('set the private key of', host)

    def delete(self, host):
        self.store.delete(self.signed_in_user.id, host.id)
        self.log_action('deleted', host)
        self.redirect(SAVED_HOSTS_URL, status=303)

    actions = {
        'details': change_details,
        'password': set_password,
        'key': set_key,
        'delete': delete,
    }
