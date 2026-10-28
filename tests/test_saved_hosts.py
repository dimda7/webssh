import json
import os
import re
import stat
import threading

from tests.sshserver import run_ssh_server
from tests.test_admin import AdminTestBase
from tests.test_app import OtherTestBase
from webssh.worker import clients
from tests.utils import (
    encode_multipart_formdata, make_tests_data_path, read_file
)


PRIVATE_KEY = read_file(make_tests_data_path('user_rsa_key'))


class SavedHostsTestBase(AdminTestBase):

    sshserver_port = 4600

    def setUp(self):
        self.running = True
        SavedHostsTestBase.sshserver_port += 1
        thread = threading.Thread(
            target=run_ssh_server,
            args=(self.sshserver_port, self.running, [])
        )
        thread.daemon = True
        thread.start()
        super(SavedHostsTestBase, self).setUp()

    def tearDown(self):
        self.running = False
        # close the terminals opened here, so they do not count towards
        # the connection limit of the next tests
        for workers in list(clients.values()):
            for worker in list(workers.values()):
                if not worker:
                    continue
                try:
                    worker.close(reason='test over')
                except (EOFError, OSError):
                    # the test SSH server has already hung up
                    pass
        clients.clear()
        super(SavedHostsTestBase, self).tearDown()

    def connect(self, **fields):
        body = dict(hostname='127.0.0.1', port=str(self.sshserver_port),
                    _xsrf='yummy')
        body.update(fields)
        response = self.request('/', 'POST', body, headers={
            'X-Requested-With': 'XMLHttpRequest'})
        self.assertEqual(response.code, 200)
        return json.loads(response.body)

    def connect_with_key(self, privatekey=PRIVATE_KEY, **fields):
        body = dict(hostname='127.0.0.1', port=str(self.sshserver_port),
                    _xsrf='yummy')
        body.update(fields)
        content_type, body = encode_multipart_formdata(
            body.items(), [('privatekey', 'user_rsa_key', privatekey)])
        response = self.request('/', 'POST', body, headers={
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': content_type})
        self.assertEqual(response.code, 200)
        return json.loads(response.body)

    def connect_saved_host(self, saved_host, **fields):
        body = dict(saved_host=saved_host, _xsrf='yummy')
        body.update(fields)
        response = self.request('/', 'POST', body, headers={
            'X-Requested-With': 'XMLHttpRequest'})
        self.assertEqual(response.code, 200)
        return json.loads(response.body)

    def save_host(self, name='dev box', **credentials):
        credentials = credentials or dict(username='robey', password='foo')
        data = self.connect(save='on', name=name, **credentials)
        self.assertIsNone(data['status'])

    def saved_host_id(self, name):
        """The Saved Host's id, found the way the Connect page offers it."""
        body = self.request('/').body.decode()
        match = re.search(r'data-saved-host="(\d+)"[^>]*>\s*{}\s*<'.format(
            re.escape(name)), body)
        self.assertIsNotNone(match, name)
        return match.group(1)

    def saved_hosts_page(self):
        response = self.request('/hosts')
        self.assertEqual(response.code, 200)
        return response.body.decode()


class TestSaveOnConnect(SavedHostsTestBase):

    def test_connect_form_offers_to_save(self):
        self.sign_in()
        body = self.request('/').body
        self.assertIn(b'name="save"', body)
        self.assertIn(b'name="name"', body)
        self.assertIn(b'href="/hosts"', body)

    def test_successful_connect_with_save_creates_saved_host(self):
        self.sign_in()
        data = self.connect(username='robey', password='foo', save='on',
                            name='dev box')
        self.assertIsNone(data['status'])

        page = self.saved_hosts_page()
        self.assertIn('dev box', page)
        self.assertIn('robey@127.0.0.1:{}'.format(self.sshserver_port), page)
        self.assertIn('password set', page)

    def test_failed_connect_saves_nothing(self):
        self.sign_in()
        data = self.connect(username='robey', password='wrong', save='on',
                            name='dev box')
        self.assertEqual(data['status'], 'Authentication failed.')
        self.assertNotIn('dev box', self.saved_hosts_page())

    def test_save_without_name_is_refused_before_connecting(self):
        self.sign_in()
        data = self.connect(username='robey', password='foo', save='on')
        self.assertEqual(data['status'], 'Name the saved host.')
        self.assertIsNone(data['id'])

    def test_taken_name_is_refused_before_connecting(self):
        self.sign_in()
        self.connect(username='robey', password='foo', save='on',
                     name='dev box')
        data = self.connect(username='bar', password='foo', save='on',
                            name='dev box')
        self.assertEqual(data['status'],
                         'Saved host name is taken: dev box')
        self.assertIsNone(data['id'])
        self.assertNotIn('bar@', self.saved_hosts_page())

    def test_save_without_password_or_key_is_refused_before_connecting(self):
        self.sign_in()
        data = self.connect(username='robey', password='', save='on',
                            name='dev box')
        self.assertEqual(data['status'],
                         'A saved host needs a password or a private key.')
        self.assertNotIn('dev box', self.saved_hosts_page())

    def test_connect_without_save_saves_nothing(self):
        self.sign_in()
        self.connect(username='robey', password='foo', name='dev box')
        self.assertNotIn('dev box', self.saved_hosts_page())

    def test_different_users_may_use_the_same_name(self):
        self.add_user('bob')
        self.sign_in()
        self.connect(username='robey', password='foo', save='on',
                     name='dev box')
        self.sign_in_as('bob')
        page = self.saved_hosts_page()
        self.assertNotIn('dev box', page)

        data = self.connect(username='bar', password='foo', save='on',
                            name='dev box')
        self.assertIsNone(data['status'])
        page = self.saved_hosts_page()
        self.assertIn('bar@127.0.0.1', page)
        self.assertNotIn('robey@', page)


class TestConnectFromSavedHost(SavedHostsTestBase):

    def test_saved_host_with_password_connects_by_id_alone(self):
        self.sign_in()
        self.save_host()
        data = self.connect_saved_host(self.saved_host_id('dev box'))
        self.assertIsNone(data['status'])
        self.assertIsNotNone(data['id'])

    def test_saved_host_with_key_connects_by_id_alone(self):
        self.sign_in()
        data = self.connect_with_key(username='keyonly', save='on',
                                     name='key box')
        self.assertIsNone(data['status'])
        self.assertIn('key set', self.saved_hosts_page())

        data = self.connect_saved_host(self.saved_host_id('key box'))
        self.assertIsNone(data['status'])
        self.assertIsNotNone(data['id'])

    def test_totp_is_sent_along_with_the_saved_host(self):
        self.sign_in()
        self.save_host('2fa box', username='pass2fa', password='password',
                       totp='passcode')
        host_id = self.saved_host_id('2fa box')

        data = self.connect_saved_host(host_id)
        self.assertEqual(data['status'], 'Need a verification code for 2fa.')

        # the failed Connect left the Saved Host as it was
        data = self.connect_saved_host(host_id, totp='passcode')
        self.assertIsNone(data['status'])

    def test_another_users_saved_host_is_refused_like_a_missing_one(self):
        self.add_user('bob')
        self.sign_in()
        self.save_host()
        host_id = self.saved_host_id('dev box')

        self.sign_in_as('bob')
        data = self.connect_saved_host(host_id)
        self.assertEqual(data['status'], 'Unknown saved host.')
        self.assertIsNone(data['id'])
        data = self.connect_saved_host('999999')
        self.assertEqual(data['status'], 'Unknown saved host.')


class TestManageSavedHosts(SavedHostsTestBase):

    def edit_url(self, name):
        """The Saved Host's page, found the way the list offers it."""
        match = re.search(r'<a href="(/hosts/\d+)">{}</a>'.format(
            re.escape(name)), self.saved_hosts_page())
        self.assertIsNotNone(match, name)
        return match.group(1)

    def act(self, url, action, **fields):
        body = dict(action=action, _xsrf='yummy')
        body.update(fields)
        return self.request(url, 'POST', body)

    def edit_details(self, url, **fields):
        body = dict(name='dev box', hostname='127.0.0.1',
                    port=str(self.sshserver_port), username='robey')
        body.update(fields)
        return self.act(url, 'details', **body)

    def test_details_are_changed_without_connecting(self):
        self.sign_in()
        self.save_host()
        url = self.edit_url('dev box')

        response = self.edit_details(url, name='renamed', username='bar',
                                     hostname='unreachable.invalid',
                                     port='2022')
        self.assertEqual(response.code, 303)
        page = self.saved_hosts_page()
        self.assertIn('renamed', page)
        self.assertIn('bar@unreachable.invalid:2022', page)
        self.assertNotIn('dev box', page)

    def test_rename_to_a_taken_name_is_refused(self):
        self.sign_in()
        self.save_host('one')
        self.save_host('two', username='bar', password='foo')

        response = self.edit_details(self.edit_url('two'), name='one',
                                     username='bar')
        self.assertEqual(response.code, 200)
        self.assertIn(b'You already have a saved host with this name',
                      response.body)
        self.assertIn('bar@', self.saved_hosts_page())

    def test_invalid_details_are_refused(self):
        self.sign_in()
        self.save_host()
        url = self.edit_url('dev box')
        for fields, message in [
                (dict(name=''), b'Name is required'),
                (dict(hostname='bad host'), b'Invalid hostname: bad host'),
                (dict(port='70000'), b'Invalid port: 70000'),
                (dict(port='abc'), b'Invalid port: abc'),
                (dict(port='0'), b'Invalid port: 0'),
                (dict(username=''), b'Username is required')]:
            response = self.edit_details(url, **fields)
            self.assertEqual(response.code, 200)
            self.assertIn(message, response.body)
        self.assertIn('robey@127.0.0.1', self.saved_hosts_page())

    def test_password_is_replaced_and_never_shown(self):
        self.sign_in()
        self.connect_with_key(username='robey', save='on', name='dev box')
        url = self.edit_url('dev box')

        response = self.act(url, 'password', password=' Secret-123 ')
        self.assertEqual(response.code, 303)
        self.assertIn('password set', self.saved_hosts_page())

        for page in ('/', '/hosts', url):
            body = self.request(page).body.decode()
            self.assertNotIn('Secret-123', body)
            self.assertNotIn('PRIVATE KEY', body)

        # robey gets in with the key, so failing shows the key is gone
        data = self.connect_saved_host(self.saved_host_id('dev box'))
        self.assertEqual(data['status'], 'Authentication failed.')

    def test_empty_password_is_refused(self):
        self.sign_in()
        self.save_host()
        response = self.act(self.edit_url('dev box'), 'password',
                            password='')
        self.assertIn(b'Password is required', response.body)

    def post_key(self, url, privatekey=PRIVATE_KEY, **fields):
        body = dict(action='key', _xsrf='yummy')
        body.update(fields)
        content_type, body = encode_multipart_formdata(
            body.items(), [('privatekey', 'user_rsa_key', privatekey)])
        return self.request(url, 'POST', body,
                            headers={'Content-Type': content_type})

    def test_password_is_replaced_with_a_key(self):
        self.sign_in()
        self.save_host()
        url = self.edit_url('dev box')

        response = self.post_key(url)
        self.assertEqual(response.code, 303)
        self.assertIn('key set', self.saved_hosts_page())
        self.assertNotIn('PRIVATE KEY', self.request(url).body.decode())

        self.edit_details(url, username='keyonly')
        data = self.connect_saved_host(self.saved_host_id('dev box'))
        self.assertIsNone(data['status'])

    def test_passphrase_is_never_shown(self):
        self.sign_in()
        self.save_host()
        url = self.edit_url('dev box')
        key = read_file(make_tests_data_path('test_rsa_password.key'))

        response = self.post_key(url, privatekey=key, passphrase='television')
        self.assertEqual(response.code, 303)

        data = self.connect_saved_host(self.saved_host_id('dev box'))
        self.assertEqual(data['status'], 'Authentication failed.')
        for body in [json.dumps(data)] + [
                self.request(page).body.decode()
                for page in ('/', '/hosts', url)]:
            self.assertNotIn('television', body)
            self.assertNotIn('PRIVATE KEY', body)

    def test_invalid_key_is_refused(self):
        self.sign_in()
        self.save_host()
        url = self.edit_url('dev box')

        response = self.post_key(url, privatekey='not a key')
        self.assertIn(b'Invalid private key or wrong passphrase',
                      response.body)
        self.assertIn('password set', self.saved_hosts_page())

    def test_deleted_saved_host_is_gone(self):
        self.sign_in()
        self.save_host()
        host_id = self.saved_host_id('dev box')
        url = self.edit_url('dev box')

        response = self.act(url, 'delete')
        self.assertEqual(response.code, 303)
        self.assertEqual(response.headers['Location'], '/hosts')
        self.assertNotIn('dev box', self.saved_hosts_page())
        self.assertEqual(self.request(url).code, 404)
        data = self.connect_saved_host(host_id)
        self.assertEqual(data['status'], 'Unknown saved host.')

    def test_another_users_saved_host_page_is_not_found(self):
        self.add_user('bob')
        self.sign_in()
        self.save_host()
        url = self.edit_url('dev box')

        self.sign_in_as('bob')
        self.assertEqual(self.request(url).code, 404)
        self.assertEqual(self.act(url, 'delete').code, 404)
        self.assertEqual(self.request('/hosts/999999').code, 404)

        self.sign_in()
        self.assertIn('dev box', self.saved_hosts_page())

    def test_saved_host_pages_need_sign_in(self):
        self.sign_in()
        self.save_host()
        url = self.edit_url('dev box')
        self.jar = {'_xsrf': 'yummy'}

        for page in ('/hosts', url):
            response = self.request(page)
            self.assertEqual(response.code, 303)
            self.assertTrue(response.headers['Location'].startswith(
                '/auth/signin'))
        response = self.act(url, 'delete')
        self.assertEqual(response.code, 303)
        self.sign_in()
        self.assertIn('dev box', self.saved_hosts_page())



class TestSavedHostsOfDeactivatedUser(SavedHostsTestBase):

    def test_saved_hosts_come_back_after_reactivation(self):
        self.add_user('bob')
        self.sign_in_as('bob')
        self.save_host()
        host_id = self.saved_host_id('dev box')
        bob = dict(self.jar)

        self.sign_in()
        self.act('bob', 'deactivate')
        self.jar = bob
        response = self.request('/', 'POST', dict(
            saved_host=host_id, _xsrf='yummy'), headers={
            'X-Requested-With': 'XMLHttpRequest'})
        self.assertEqual(response.code, 401)
        self.assertEqual(self.sign_in_as_status('bob'), 200)

        self.sign_in()
        self.act('bob', 'activate')
        self.sign_in_as('bob')
        self.assertIn('dev box', self.saved_hosts_page())
        self.assertIsNone(self.connect_saved_host(host_id)['status'])

    def sign_in_as_status(self, username):
        self.jar = {'_xsrf': 'yummy'}
        return self.sign_in(username=username, password='password1').code


class TestUsersDatabaseFileMode(SavedHostsTestBase):

    def prepare_db(self):
        # a file left readable by others before this release
        open(self.authdb, 'w').close()
        os.chmod(self.authdb, 0o644)

    def test_database_file_is_readable_only_by_webssh(self):
        mode = stat.S_IMODE(os.stat(self.authdb).st_mode)
        self.assertEqual(mode, 0o600)



class TestWithoutSignIn(OtherTestBase):

    def test_connect_works_as_before_and_saves_nothing(self):
        body = dict(self.body, save='on', name='dev box', saved_host='1')
        response = self.sync_post('/', body)
        self.assert_status_none(json.loads(response.body))

    def test_no_saved_hosts_anywhere(self):
        body = self.fetch('/').body
        self.assertNotIn(b'saved-host', body)
        self.assertNotIn(b'name="save"', body)
        self.assertEqual(self.fetch('/hosts').code, 404)
