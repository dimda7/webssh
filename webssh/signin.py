import functools
import json
import logging
import sqlite3
import time

from collections import deque

import bcrypt


# bcrypt only looks at the first 72 bytes and bcrypt>=5 refuses longer input
MAX_PASSWORD_BYTES = 72

SCHEMA = '''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    firstname TEXT,
    lastname TEXT,
    middlename TEXT,
    password TEXT,
    active BOOLEAN NOT NULL DEFAULT 1
)
'''


class ConfigError(Exception):
    """Sign-in is misconfigured, webssh can not start."""


class User(object):

    def __init__(self, id, username, firstname, lastname, middlename,
                 password, active):
        self.id = id
        self.username = username
        self.password = password
        # hand-edited rows may hold 'false' or 'no': anything but an
        # explicit yes counts as inactive
        self.active = str(active).strip().lower() in ('1', 'true')
        self.fullname = ' '.join(
            filter(None, [lastname, firstname, middlename])
        ) or username


def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


class UserStore(object):

    def __init__(self, path):
        self.path = path
        try:
            self.conn = sqlite3.connect(path)
            with self.conn:
                self.conn.execute(SCHEMA)
        except sqlite3.Error as exc:
            raise ConfigError('Can not open {!r}: {}'.format(path, exc))

    def is_empty(self):
        return self.conn.execute('SELECT 1 FROM users LIMIT 1').fetchone() \
            is None

    def add(self, username, password):
        with self.conn:
            self.conn.execute(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                (username, hash_password(password))
            )

    def _find_by(self, column, value):
        row = self.conn.execute(
            'SELECT id, username, firstname, lastname, middlename, password, '
            'active FROM users WHERE {} = ?'.format(column), (value,)
        ).fetchone()
        return User(*row) if row else None

    def find(self, username):
        return self._find_by('username', username)

    def find_by_id(self, user_id):
        return self._find_by('id', user_id)

    def bootstrap(self, username, password):
        """Creates the first user, if the table is empty."""
        if not self.is_empty():
            if username or password:
                logging.warning(
                    'users table is not empty, WSSH_INIT_* ignored'
                )
            return

        if not username or not password:
            raise ConfigError(
                'No users in {!r} and WSSH_INIT_USER/WSSH_INIT_PASSWORD '
                'not set'.format(self.path)
            )
        if len(password.encode()) > MAX_PASSWORD_BYTES:
            raise ConfigError('WSSH_INIT_PASSWORD must be at most {} bytes'
                              .format(MAX_PASSWORD_BYTES))
        self.add(username, password)
        logging.info('Created user {!r}'.format(username))


@functools.lru_cache(maxsize=None)
def dummy_hash():
    return hash_password('webssh-dummy-password')


def check_password(user, password):
    """True if the user is active and the password is theirs.

    bcrypt runs even when there is no such user, so that the response time
    does not tell which usernames exist. Slow: keep it off the IOLoop.
    """
    secret = password.encode()
    if len(secret) > MAX_PASSWORD_BYTES:
        return False
    hashed = user.password if user else None
    try:
        matched = bcrypt.checkpw(secret, (hashed or dummy_hash()).encode())
    except ValueError:
        logging.warning(
            'Password of user {!r} is not a bcrypt hash'.format(user.username)
        )
        return False
    return bool(hashed and matched and user.active)


class Session(object):
    """What the signed session cookie holds about the signed-in user.

    Only the id: everything else about the user is read from the DB, so
    edits there take effect at once.
    """

    def __init__(self, user_id, last_activity):
        self.user_id = user_id
        self.last_activity = last_activity

    @classmethod
    def for_user(cls, user):
        return cls(user.id, time.time())

    @classmethod
    def from_json(cls, value):
        try:
            data = json.loads(value)
            session = cls(data['user_id'], float(data['last_activity']))
        except (ValueError, TypeError, KeyError):
            return None
        return session if session.user_id else None

    def to_json(self):
        return json.dumps(dict(user_id=self.user_id,
                               last_activity=self.last_activity))

    def is_expired(self, timeout):
        return time.time() - self.last_activity > timeout

    def touch(self):
        self.last_activity = time.time()


class SignInLimiter(object):
    """Counts sign-in attempts per client IP within a sliding window.

    An attempt counts from the moment it starts; a successful one is
    forgotten, together with earlier failures for the same username only.
    """

    limit = 5
    window = 300

    def __init__(self):
        self.attempts = {}
        self.last_sweep = time.time()

    def prune(self, ip):
        attempts = self.attempts.get(ip)
        threshold = time.time() - self.window
        while attempts and attempts[0][0] < threshold:
            attempts.popleft()
        if attempts is not None and not attempts:
            del self.attempts[ip]

    def sweep(self):
        # IPs that never come back are dropped once per window, not on
        # every attempt
        if time.time() - self.last_sweep < self.window:
            return
        self.last_sweep = time.time()
        for ip in list(self.attempts):
            self.prune(ip)

    def is_blocked(self, ip):
        self.sweep()
        self.prune(ip)
        return len(self.attempts.get(ip, ())) >= self.limit

    def add_attempt(self, ip, username):
        self.attempts.setdefault(ip, deque()).append((time.time(), username))

    def forget(self, ip, username):
        attempts = deque(a for a in self.attempts.get(ip, ())
                         if a[1] != username)
        if attempts:
            self.attempts[ip] = attempts
        else:
            self.attempts.pop(ip, None)


def safe_next_url(url):
    """The page to return to after sign-in: a path on this site, or '/'."""
    # '//host' and '/\\host' are taken by browsers as another site
    if not url.startswith('/') or url.startswith('//') or \
            url.startswith('/\\'):
        return '/'
    return url
