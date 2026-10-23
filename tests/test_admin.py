import json
import re
import sqlite3
import time

import tornado.gen

from tornado.options import options
from tornado.testing import AsyncHTTPTestCase
from tornado.web import create_signed_value
from tests.test_auth import SignInTestBase, urlencode
from webssh.main import make_app, make_handlers
from webssh.settings import get_app_settings
from webssh.signin import hash_password


class AdminTestBase(SignInTestBase):

    def add_user(self, username, password='password1', is_admin=0,
                 active=1):
        conn = sqlite3.connect(self.authdb)
        with conn:
            conn.execute(
                'INSERT INTO users (username, password, is_admin, active) '
                'VALUES (?, ?, ?, ?)',
                (username, hash_password(password), is_admin, active)
            )
        conn.close()

    def user_url(self, username):
        """The user's page, found the way an Administrator finds it."""
        body = self.request('/admin/users').body.decode()
        match = re.search(
            r'<a href="(/admin/users/\d+)">{}</a>'.format(re.escape(username)),
            body
        )
        self.assertIsNotNone(match, username)
        return match.group(1)

    def act(self, username, action, **fields):
        body = dict(action=action, _xsrf='yummy')
        body.update(fields)
        return self.request(self.user_url(username), 'POST', body)

    def sign_in_as(self, username, password='password1'):
        self.jar = {'_xsrf': 'yummy'}
        response = self.sign_in(username=username, password=password)
        self.assertEqual(response.code, 303)
        return response


class TestAdministratorAccess(AdminTestBase):

    def test_init_user_is_an_administrator(self):
        self.sign_in()
        self.assertIn(b'href="/admin/users"', self.request('/').body)
        response = self.request('/admin/users')
        self.assertEqual(response.code, 200)
        self.assertIn(b'alice', response.body)

    def test_user_who_is_not_an_administrator_gets_403(self):
        self.add_user('bob')
        self.sign_in_as('bob')
        self.assertNotIn(b'href="/admin/users"', self.request('/').body)

        response = self.request('/admin/users')
        self.assertEqual(response.code, 403)
        self.assertIn(b'Only administrators can manage users', response.body)


class TestCreateUser(AdminTestBase):

    def create(self, **fields):
        body = dict(username='bob', password='password1',
                    password2='password1', firstname='', lastname='',
                    middlename='', _xsrf='yummy')
        body.update(fields)
        return self.request('/admin/users', 'POST', body)

    def assert_create_refused(self, message, **fields):
        response = self.create(firstname='Robert', **fields)
        self.assertEqual(response.code, 200)
        self.assertIn(message.encode(), response.body)
        # what was typed, except passwords, is kept
        self.assertIn(b'value="Robert"', response.body)
        self.assertNotIn(b'value="password1"', response.body)

    def setUp(self):
        super(TestCreateUser, self).setUp()
        self.sign_in()

    def test_created_user_can_sign_in(self):
        response = self.create(firstname='Robert', lastname='Smith')
        self.assertEqual(response.code, 303)
        self.assertEqual(response.headers['Location'], '/admin/users')
        self.assertIn(b'Smith Robert', self.request('/admin/users').body)

        self.sign_in_as('bob')
        self.assertNotIn(b'href="/admin/users"', self.request('/').body)

    def test_created_administrator_can_manage_users(self):
        self.create(is_administrator='on')
        self.sign_in_as('bob')
        self.assertEqual(self.request('/admin/users').code, 200)

    def test_invalid_username_is_refused(self):
        for username in ('', 'bob smith', 'боб', 'b' * 65, 'bob/1'):
            self.assert_create_refused(
                'Username must be 1 to 64 Latin letters, digits',
                username=username
            )

    def test_username_taken_in_another_case_is_refused(self):
        self.assert_create_refused('Username is taken', username='ALICE')

    def test_short_password_is_refused(self):
        self.assert_create_refused('at least 8 characters',
                                   password='short', password2='short')

    def test_password_over_72_bytes_is_refused(self):
        self.assert_create_refused('at most 72 bytes', password='я' * 37,
                                   password2='я' * 37)

    def test_mismatched_passwords_are_refused(self):
        self.assert_create_refused('Passwords do not match',
                                   password2='password2')

    def test_concurrent_creates_in_different_case_make_one_user(self):
        bodies = [urlencode(dict(username=name, password='password1',
                                 password2='password1', _xsrf='yummy'))
                  for name in ('bob', 'Bob', 'bob')]
        cookie = self.cookie_header()

        @tornado.gen.coroutine
        def create_all():
            responses = yield [self.http_client.fetch(
                self.get_url('/admin/users'), method='POST', body=body,
                headers={'Cookie': cookie}, follow_redirects=False,
                raise_error=False
            ) for body in bodies]
            return responses

        responses = self.io_loop.run_sync(create_all, timeout=30)
        self.assertEqual(sorted(r.code for r in responses), [200, 200, 303])
        for response in responses:
            if response.code == 200:
                self.assertIn(b'Username is taken', response.body)

    def test_password_is_taken_verbatim(self):
        self.create(password=' spaced pw ', password2=' spaced pw ')
        self.sign_in_as('bob', ' spaced pw ')


class TestEditUser(AdminTestBase):

    def setUp(self):
        super(TestEditUser, self).setUp()
        self.add_user('bob')
        self.sign_in()

    def test_names_are_shown_to_the_user(self):
        url = self.user_url('bob')
        response = self.act('bob', 'names', firstname='Robert',
                            lastname='Smith', middlename='')
        self.assertEqual(response.code, 303)
        self.assertEqual(response.headers['Location'], url)
        self.assertIn(b'value="Robert"', self.request(url).body)

        self.sign_in_as('bob')
        self.assertIn(b'Smith Robert', self.request('/').body)

    def test_unknown_user_is_404(self):
        for user_id in ('999', '9' * 30):
            self.assertEqual(
                self.request('/admin/users/' + user_id).code, 404, user_id)


class TestSetPassword(AdminTestBase):

    def setUp(self):
        super(TestSetPassword, self).setUp()
        self.add_user('bob')
        self.sign_in_as('bob')
        self.bob_jar = self.jar
        self.sign_in_as(self.init_user, self.init_password)

    def test_new_password_works_and_old_one_does_not(self):
        response = self.act('bob', 'password', password='new password',
                            password2='new password')
        self.assertEqual(response.code, 303)

        self.jar = {'_xsrf': 'yummy'}
        self.assertIn(b'Invalid username or password',
                      self.sign_in(username='bob', password='password1').body)
        self.sign_in_as('bob', 'new password')

    def test_setting_a_password_signs_the_user_out_everywhere(self):
        self.act('bob', 'password', password='new password',
                 password2='new password')
        self.jar = self.bob_jar
        response = self.request('/')
        self.assertEqual(response.code, 303)
        self.assertTrue(response.headers['Location'].startswith('/auth/signin'))

    def test_password_rules_apply(self):
        response = self.act('bob', 'password', password='short',
                            password2='short')
        self.assertEqual(response.code, 200)
        self.assertIn(b'at least 8 characters', response.body)
        self.jar = self.bob_jar
        self.assertEqual(self.request('/').code, 200)


class TestDeactivateAndAdministration(AdminTestBase):

    def setUp(self):
        super(TestDeactivateAndAdministration, self).setUp()
        self.add_user('bob')
        self.sign_in_as('bob')
        self.bob_jar = self.jar
        self.sign_in_as(self.init_user, self.init_password)

    def as_bob(self, url='/'):
        admin_jar, self.jar = self.jar, self.bob_jar
        try:
            return self.request(url)
        finally:
            self.jar = admin_jar

    def test_deactivated_user_is_signed_out_and_can_not_sign_in(self):
        self.assertEqual(self.act('bob', 'deactivate').code, 303)
        self.assertEqual(self.as_bob().code, 303)

        self.jar = {'_xsrf': 'yummy'}
        self.assertIn(b'Invalid username or password',
                      self.sign_in(username='bob', password='password1').body)

    def test_reactivation_does_not_bring_back_old_sessions(self):
        self.act('bob', 'deactivate')
        self.act('bob', 'activate')
        self.assertEqual(self.as_bob().code, 303)

    def test_deactivate_says_open_terminals_stay_open(self):
        body = self.request(self.user_url('bob')).body
        self.assertIn(b'Terminals that are already open stay connected',
                      body[body.index(b'value="deactivate"'):])

    def test_reactivated_user_can_sign_in_again(self):
        self.act('bob', 'deactivate')
        self.act('bob', 'activate')
        self.sign_in_as('bob')

    def test_granted_and_revoked_administration_apply_at_once(self):
        self.act('bob', 'grant')
        self.assertEqual(self.as_bob('/admin/users').code, 200)
        self.act('bob', 'revoke')
        self.assertEqual(self.as_bob('/admin/users').code, 403)

    def test_administrator_sets_own_password_only_in_their_profile(self):
        url = self.user_url(self.init_user)
        self.assertNotIn(b'id="password"', self.request(url).body)

        response = self.act(self.init_user, 'password',
                            password='new password', password2='new password')
        self.assertEqual(response.code, 200)
        self.assertIn(b'Change your own password in My profile',
                      response.body)
        self.assertEqual(self.request('/').code, 200)
        self.jar = {'_xsrf': 'yummy'}
        self.sign_in_as(self.init_user, self.init_password)

    def test_administrator_can_not_deactivate_themselves(self):
        response = self.act(self.init_user, 'deactivate')
        self.assertEqual(response.code, 200)
        self.assertIn(b'You can not deactivate yourself', response.body)
        self.assertEqual(self.request('/admin/users').code, 200)

    def test_administrator_can_not_revoke_their_own_administration(self):
        response = self.act(self.init_user, 'revoke')
        self.assertEqual(response.code, 200)
        self.assertIn(b'You can not revoke your own administration',
                      response.body)
        self.assertEqual(self.request('/admin/users').code, 200)


class TestProfile(AdminTestBase):

    def setUp(self):
        super(TestProfile, self).setUp()
        self.add_user('bob')
        self.sign_in_as('bob')
        self.other_jar = self.jar
        self.sign_in_as('bob')

    def in_other_browser(self, url='/'):
        jar, self.jar = self.jar, self.other_jar
        try:
            return self.request(url)
        finally:
            self.jar = jar

    def change_password(self, current='password1', new='new password',
                        repeated=None):
        return self.request('/account', 'POST', dict(
            action='password', current=current, password=new,
            password2=new if repeated is None else repeated, _xsrf='yummy'
        ))

    def test_every_user_has_a_profile_link(self):
        self.assertIn(b'href="/account">My profile<', self.request('/').body)
        self.assertEqual(self.request('/account').code, 200)

    def test_wrong_current_password_is_refused(self):
        response = self.change_password(current='wrong')
        self.assertEqual(response.code, 200)
        self.assertIn(b'Current password is wrong', response.body)

    def test_password_rules_apply(self):
        response = self.change_password(new='short')
        self.assertIn(b'at least 8 characters', response.body)
        response = self.change_password(repeated='other password')
        self.assertIn(b'Passwords do not match', response.body)

    def test_change_keeps_this_browser_and_ends_other_sessions(self):
        response = self.change_password()
        self.assertEqual(response.code, 303)
        self.assertEqual(response.headers['Location'], '/account')

        self.assertEqual(self.request('/').code, 200)
        self.assertEqual(self.in_other_browser().code, 303)
        self.sign_in_as('bob', 'new password')

    def test_profile_says_open_terminals_stay_open(self):
        self.assertIn(b'Terminals that are already open stay connected',
                      self.request('/account').body)

    def test_guessing_the_current_password_is_limited(self):
        for _ in range(5):
            response = self.change_password(current='wrong')
            self.assertIn(b'Current password is wrong', response.body)
        response = self.change_password()
        self.assertIn(b'Too many attempts, try later', response.body)
        self.assertEqual(self.in_other_browser().code, 200)

    def test_failed_sign_ins_from_the_same_ip_do_not_block_the_profile(self):
        jar = self.jar
        self.jar = {'_xsrf': 'yummy'}
        for _ in range(5):
            self.sign_in(username='nobody', password='wrong')
        self.jar = jar
        self.assertEqual(self.change_password().code, 303)

    def test_failed_current_passwords_do_not_block_sign_in(self):
        for _ in range(5):
            self.change_password(current='wrong')
        self.sign_in_as(self.init_user, self.init_password)

    def test_request_with_the_old_cookie_does_not_clear_the_new_one(self):
        old_cookie = self.jar['wssh_session']
        self.change_password()
        new_cookie = self.jar['wssh_session']

        response = self.fetch('/', headers={
            'Cookie': '_xsrf=yummy; wssh_session=' + old_cookie},
            follow_redirects=False)
        self.assertEqual(response.code, 303)
        self.assertFalse([c for c in response.headers.get_list('Set-Cookie')
                          if c.startswith('wssh_session=')])
        self.assertEqual(self.jar['wssh_session'], new_cookie)
        self.assertEqual(self.request('/').code, 200)

    def test_sign_out_everywhere_ends_all_sessions(self):
        response = self.request('/account', 'POST', dict(
            action='signout_everywhere', _xsrf='yummy'))
        self.assertEqual(response.code, 303)
        self.assertEqual(response.headers['Location'], '/auth/signin')

        self.assertEqual(self.request('/').code, 303)
        self.assertEqual(self.in_other_browser().code, 303)


class TestUpgradeFromDatabaseWithoutAdministration(AdminTestBase):

    init_user = None
    init_password = None

    def prepare_db(self):
        # the users table as the first release of sign-in created it
        conn = sqlite3.connect(self.authdb)
        with conn:
            conn.execute(
                'CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, '
                'username TEXT NOT NULL UNIQUE, firstname TEXT, '
                'lastname TEXT, middlename TEXT, password TEXT, '
                'active BOOLEAN NOT NULL DEFAULT 1)'
            )
            for username, active in (('old', 0), ('carol', 1), ('dave', 1)):
                conn.execute(
                    'INSERT INTO users (username, password, active) '
                    'VALUES (?, ?, ?)',
                    (username, hash_password('password1'), active)
                )
        conn.close()

    def test_oldest_active_user_becomes_administrator(self):
        self.sign_in_as('carol')
        self.assertEqual(self.request('/admin/users').code, 200)

    def test_other_users_do_not(self):
        self.sign_in_as('dave')
        self.assertEqual(self.request('/admin/users').code, 403)


class TestAdministrationIsProtected(AdminTestBase):

    def setUp(self):
        super(TestAdministrationIsProtected, self).setUp()
        self.sign_in()

    def test_posts_without_xsrf_token_are_refused(self):
        bob = dict(username='bob', password='password1',
                   password2='password1')
        self.assertEqual(self.request('/admin/users', 'POST', bob).code, 403)
        url = self.user_url(self.init_user)
        self.assertEqual(self.request(url, 'POST', dict(action='grant')).code,
                         403)
        self.assertEqual(self.request('/account', 'POST', dict(
            action='signout_everywhere')).code, 403)
        self.assertNotIn(b'>bob<', self.request('/admin/users').body)

    def test_actions_are_logged_without_passwords(self):
        with self.assertLogs(level='INFO') as logs:
            self.request('/admin/users', 'POST', dict(
                username='bob', password='secret pw1', password2='secret pw1',
                _xsrf='yummy'))
        output = '\n'.join(logs.output)
        self.assertIn("Administrator 'alice' created user 'bob'", output)
        self.assertNotIn('secret pw1', output)


class TestNoAdministrationWithoutSignIn(AsyncHTTPTestCase):

    def get_app(self):
        options.authdb = ''
        options.xsrf = True
        options.debug = False
        options.origin = 'same'
        options.hostfile = ''
        options.syshostfile = ''
        options.tdstream = ''
        return make_app(make_handlers(self.io_loop, options),
                        get_app_settings(options))

    def test_admin_and_account_pages_do_not_exist(self):
        for url in ('/admin/users', '/admin/users/1', '/account'):
            self.assertEqual(self.fetch(url).code, 404, url)


class TestSessionsFromBeforeAdministration(AdminTestBase):

    def cookie(self, value):
        return create_signed_value(self.cookiesecret, 'wssh_session',
                                   value).decode()

    def test_cookie_without_session_version_still_works(self):
        self.jar['wssh_session'] = self.cookie(json.dumps(
            dict(user_id=1, last_activity=time.time())))
        self.assertEqual(self.request('/').code, 200)

    def test_unreadable_cookie_is_cleared(self):
        self.jar['wssh_session'] = self.cookie('not json')
        self.assertEqual(self.request('/').code, 303)
        self.assertNotIn('wssh_session', self.jar)
