import json
import os
import shutil
import sqlite3
import time
import unittest
import tempfile
import threading

from http.cookies import SimpleCookie
from unittest import mock

import tornado.gen
import tornado.websocket

from tornado.httpclient import HTTPClientError, HTTPRequest
from tornado.testing import AsyncHTTPTestCase, gen_test
from tornado.options import options
from tests.sshserver import run_ssh_server, banner
from webssh.signin import ConfigError, hash_password
from webssh.main import make_app, make_handlers
from webssh.settings import get_app_settings, get_server_settings
from webssh.utils import to_str

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode


class SignInTestBase(AsyncHTTPTestCase):

    cookiesecret = 'ab' * 32
    init_user = 'alice'
    init_password = 'wonderland'
    authtimeout = 3600.0

    def get_httpserver_options(self):
        return get_server_settings(options)

    def get_app(self):
        self.tmpdir = tempfile.mkdtemp()
        self.authdb = os.path.join(self.tmpdir, 'users.db')
        self.jar = {'_xsrf': 'yummy'}

        env = {}
        if self.init_user is not None:
            env['WSSH_INIT_USER'] = self.init_user
        if self.init_password is not None:
            env['WSSH_INIT_PASSWORD'] = self.init_password
        self.env_patch = mock.patch.dict(os.environ, env)
        self.env_patch.start()

        options.debug = False
        options.xsrf = True
        options.policy = 'warning'
        options.hostfile = ''
        options.syshostfile = ''
        options.tdstream = ''
        options.maxconn = 20
        options.origin = 'same'
        options.authdb = self.authdb
        options.cookiesecret = self.cookiesecret
        options.authtimeout = self.authtimeout
        return make_app(make_handlers(self.io_loop, options),
                        get_app_settings(options))

    def tearDown(self):
        super(SignInTestBase, self).tearDown()
        options.authdb = ''
        options.cookiesecret = ''
        options.authtimeout = 3600.0
        self.env_patch.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def cookie_header(self):
        return '; '.join('{}={}'.format(k, v) for k, v in self.jar.items())

    def request(self, url, method='GET', body=None, headers=None):
        headers = dict(headers or {})
        headers['Cookie'] = self.cookie_header()
        if isinstance(body, dict):
            body = urlencode(body)
        response = self.fetch(url, method=method, body=body, headers=headers,
                              follow_redirects=False)
        for header in response.headers.get_list('Set-Cookie'):
            for name, morsel in SimpleCookie(header).items():
                if morsel['expires'] and not morsel.value:
                    self.jar.pop(name, None)
                else:
                    self.jar[name] = morsel.value
        return response

    def sign_in(self, username=None, password=None):
        body = dict(
            username=self.init_user if username is None else username,
            password=self.init_password if password is None else password,
            _xsrf='yummy'
        )
        return self.request('/auth/signin', 'POST', body)


class TestSignIn(SignInTestBase):

    def test_protected_page_redirects_to_signin_without_session(self):
        response = self.request('/')
        self.assertEqual(response.code, 303)
        self.assertEqual(response.headers['Location'], '/auth/signin')

    def test_user_from_init_env_can_sign_in_and_open_connect_form(self):
        response = self.sign_in()
        self.assertEqual(response.code, 303)
        self.assertEqual(response.headers['Location'], '/')

        response = self.request('/')
        self.assertEqual(response.code, 200)
        self.assertIn(b'id="connect"', response.body)

    def assert_signin_rejected(self, response):
        self.assertEqual(response.code, 200)
        self.assertIn(b'Invalid username or password', response.body)
        self.assertNotIn('wssh_session', self.jar)

    def test_wrong_password_is_rejected(self):
        self.assert_signin_rejected(self.sign_in(password='wrong'))

    def test_unknown_username_is_rejected_with_the_same_message(self):
        self.assert_signin_rejected(self.sign_in(username='nobody'))

    def test_inactive_user_is_rejected_with_the_same_message(self):
        conn = sqlite3.connect(self.authdb)
        with conn:
            conn.execute(
                'INSERT INTO users (username, password, active) '
                'VALUES (?, ?, 0)', ('bob', hash_password('builder'))
            )
        conn.close()
        self.assert_signin_rejected(
            self.sign_in(username='bob', password='builder')
        )

    def assert_signin_required_json(self, response):
        self.assertEqual(response.code, 401)
        self.assertTrue(
            response.headers['Content-Type'].startswith('application/json')
        )
        data = json.loads(response.body)
        self.assertIs(data['signin_required'], True)
        self.assertEqual(data['location'], '/auth/signin')

    def test_ajax_connect_without_session_gets_401_json(self):
        response = self.request(
            '/', 'POST', dict(hostname='localhost', username='robey',
                              _xsrf='yummy'),
            headers={'X-Requested-With': 'XMLHttpRequest'}
        )
        self.assert_signin_required_json(response)

    def test_ajax_connect_without_session_or_xsrf_gets_401_json(self):
        self.jar.pop('_xsrf')
        response = self.request(
            '/', 'POST', dict(hostname='localhost', username='robey'),
            headers={'X-Requested-With': 'XMLHttpRequest'}
        )
        self.assert_signin_required_json(response)

    def test_fetch_without_session_gets_401_json(self):
        response = self.request('/', headers={'Sec-Fetch-Mode': 'cors'})
        self.assert_signin_required_json(response)

    def test_browser_navigation_without_session_is_redirected(self):
        response = self.request('/', headers={'Sec-Fetch-Mode': 'navigate'})
        self.assertEqual(response.code, 303)

    @gen_test
    def test_terminal_cannot_be_opened_without_session(self):
        url = self.get_url('/ws?id=1').replace('http', 'ws')
        request = HTTPRequest(url, headers={'Sec-Fetch-Mode': 'websocket'})
        with self.assertRaises(HTTPClientError) as ctx:
            yield tornado.websocket.websocket_connect(request)
        self.assertEqual(ctx.exception.code, 401)

    def test_sign_out_ends_session(self):
        self.sign_in()
        response = self.request('/auth/signout', 'POST', dict(_xsrf='yummy'))
        self.assertEqual(response.code, 303)
        self.assertEqual(response.headers['Location'], '/auth/signin')

        response = self.request('/')
        self.assertEqual(response.code, 303)
        self.assertEqual(response.headers['Location'], '/auth/signin')

    def test_sign_out_needs_post_with_xsrf_token(self):
        self.sign_in()
        self.assertEqual(self.request('/auth/signout').code, 405)
        response = self.request('/auth/signout', 'POST', '')
        self.assertEqual(response.code, 403)
        self.assertEqual(self.request('/').code, 200)

    def test_session_cookie_ends_with_the_browser(self):
        self.sign_in()
        response = self.request('/')
        cookie = [c for c in response.headers.get_list('Set-Cookie')
                  if c.startswith('wssh_session=')][0]
        self.assertNotIn('expires', cookie.lower())
        self.assertNotIn('max-age', cookie.lower())

    def test_deactivated_user_loses_access(self):
        self.sign_in()
        conn = sqlite3.connect(self.authdb)
        with conn:
            conn.execute('UPDATE users SET active = 0 WHERE username = ?',
                         (self.init_user,))
        conn.close()

        response = self.request('/')
        self.assertEqual(response.code, 303)
        self.assertEqual(response.headers['Location'], '/auth/signin')

    def test_password_longer_than_bcrypt_limit_is_rejected(self):
        self.assert_signin_rejected(self.sign_in(password='я' * 40))

    def test_sign_in_without_xsrf_token_is_forbidden(self):
        response = self.request('/auth/signin', 'POST', dict(
            username=self.init_user, password=self.init_password
        ))
        self.assertEqual(response.code, 403)

    def test_signed_in_user_opening_signin_goes_to_connect_form(self):
        self.sign_in()
        response = self.request('/auth/signin')
        self.assertEqual(response.code, 303)
        self.assertEqual(response.headers['Location'], '/')

    def test_signin_page_is_shown_without_session(self):
        response = self.request('/auth/signin')
        self.assertEqual(response.code, 200)
        self.assertIn(b'id="signin"', response.body)


class TestSignInTimeout(SignInTestBase):

    authtimeout = 0.5

    def test_idle_session_must_sign_in_again(self):
        self.sign_in()
        time.sleep(0.6)

        response = self.request('/')
        self.assertEqual(response.code, 303)
        self.assertEqual(response.headers['Location'], '/auth/signin')
        self.assertNotIn('wssh_session', self.jar)

    def test_signin_page_is_shown_directly_for_idle_session(self):
        self.sign_in()
        time.sleep(0.6)

        response = self.request('/auth/signin')
        self.assertEqual(response.code, 200)
        self.assertIn(b'id="signin"', response.body)

    def test_activity_keeps_session_alive(self):
        self.sign_in()
        for _ in range(3):
            time.sleep(0.3)
            self.assertEqual(self.request('/').code, 200)


class TestSignInAttemptLimit(SignInTestBase):

    def test_too_many_failed_attempts_block_even_the_right_password(self):
        for _ in range(5):
            response = self.sign_in(password='wrong')
            self.assertIn(b'Invalid username or password', response.body)

        response = self.sign_in()
        self.assertEqual(response.code, 200)
        self.assertIn(b'Too many attempts, try later', response.body)
        self.assertNotIn('wssh_session', self.jar)

    def test_successful_sign_in_resets_failed_attempts(self):
        for _ in range(4):
            self.sign_in(password='wrong')
        self.assertEqual(self.sign_in().code, 303)
        self.jar.pop('wssh_session')

        for _ in range(4):
            self.sign_in(password='wrong')
        self.assertEqual(self.sign_in().code, 303)

    def test_successful_sign_in_below_the_limit(self):
        for _ in range(4):
            self.sign_in(password='wrong')
        self.assertEqual(self.sign_in().code, 303)


class TestSignInStartup(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        options.authdb = os.path.join(self.tmpdir, 'users.db')
        options.cookiesecret = 'ab' * 32
        options.xsrf = True
        options.debug = False
        options.origin = 'same'

    def tearDown(self):
        options.authdb = ''
        options.cookiesecret = ''
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def assert_refuses_to_start(self, env, message):
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ConfigError) as ctx:
                get_app_settings(options)
        self.assertIn(message, str(ctx.exception))

    def test_refuses_to_start_without_cookie_secret(self):
        options.cookiesecret = ''
        self.assert_refuses_to_start(
            dict(WSSH_INIT_USER='alice', WSSH_INIT_PASSWORD='wonderland'),
            'WSSH_COOKIE_SECRET'
        )

    def test_refuses_to_start_with_malformed_cookie_secret(self):
        options.cookiesecret = 'not-hex'
        self.assert_refuses_to_start(
            dict(WSSH_INIT_USER='alice', WSSH_INIT_PASSWORD='wonderland'),
            '32 bytes'
        )

    def test_cookie_secret_can_come_from_environment(self):
        options.cookiesecret = ''
        env = dict(WSSH_COOKIE_SECRET='cd' * 32, WSSH_INIT_USER='alice',
                   WSSH_INIT_PASSWORD='wonderland')
        with mock.patch.dict(os.environ, env, clear=True):
            settings = get_app_settings(options)
        self.assertEqual(settings['cookie_secret'], 'cd' * 32)

    def test_refuses_to_start_with_unopenable_authdb(self):
        options.authdb = os.path.join(self.tmpdir, 'missing', 'users.db')
        self.assert_refuses_to_start(
            dict(WSSH_INIT_USER='alice', WSSH_INIT_PASSWORD='wonderland'),
            'missing'
        )

    def test_refuses_to_start_with_too_long_init_password(self):
        self.assert_refuses_to_start(
            dict(WSSH_INIT_USER='alice', WSSH_INIT_PASSWORD='x' * 73),
            '72 bytes'
        )

    def test_refuses_to_start_with_no_users_and_no_init_env(self):
        self.assert_refuses_to_start({}, 'WSSH_INIT_USER')

    def test_sign_in_stays_off_without_authdb(self):
        options.authdb = ''
        with mock.patch.dict(os.environ, {}, clear=True):
            settings = get_app_settings(options)
        self.assertFalse(settings.get('signin_enabled'))


class TestSignInInitEnvIgnoredOnceUsersExist(SignInTestBase):

    def get_app(self):
        # the first start creates the user, then webssh restarts on the
        # same DB with a changed bootstrap password
        super(TestSignInInitEnvIgnoredOnceUsersExist, self).get_app()
        with mock.patch.dict(os.environ, {'WSSH_INIT_PASSWORD': 'changed'}):
            return make_app(make_handlers(self.io_loop, options),
                            get_app_settings(options))

    def test_original_password_still_works(self):
        self.assertEqual(self.sign_in().code, 303)

    def test_changed_init_password_does_not_work(self):
        response = self.sign_in(password='changed')
        self.assertIn(b'Invalid username or password', response.body)


class TestConnectAfterSignIn(SignInTestBase):

    sshserver_port = 4400

    def setUp(self):
        self.running = True
        TestConnectAfterSignIn.sshserver_port += 1
        thread = threading.Thread(
            target=run_ssh_server,
            args=(self.sshserver_port, self.running, [])
        )
        thread.daemon = True
        thread.start()
        super(TestConnectAfterSignIn, self).setUp()

    def tearDown(self):
        self.running = False
        super(TestConnectAfterSignIn, self).tearDown()

    def test_connect_form_shows_user_and_sign_out_link(self):
        self.sign_in()
        response = self.request('/')
        self.assertIn(b'alice', response.body)
        self.assertIn(b'action="/auth/signout"', response.body)

    def test_signed_in_user_can_open_terminal(self):
        self.sign_in()
        response = self.request('/', 'POST', dict(
            hostname='127.0.0.1', port=str(self.sshserver_port),
            username='robey', password='foo', _xsrf='yummy'
        ), headers={'X-Requested-With': 'XMLHttpRequest'})
        data = json.loads(response.body)
        self.assertIsNone(data['status'])

        url = self.get_url('/ws?id=' + data['id']).replace('http', 'ws')
        request = HTTPRequest(url, headers={'Cookie': self.cookie_header(),
                                            'Sec-Fetch-Mode': 'websocket'})

        @tornado.gen.coroutine
        def read_banner():
            ws = yield tornado.websocket.websocket_connect(request)
            msg = yield ws.read_message()
            ws.close()
            return msg

        msg = self.io_loop.run_sync(read_banner)
        self.assertEqual(to_str(msg, data['encoding']), banner)
