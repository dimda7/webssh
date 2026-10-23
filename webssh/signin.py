import functools
import json
import logging
import re
import sqlite3
import time

from collections import deque

import bcrypt


# bcrypt only looks at the first 72 bytes and bcrypt>=5 refuses longer input
MAX_PASSWORD_BYTES = 72
MIN_PASSWORD_LENGTH = 8
USERNAME_RE = re.compile(r'[A-Za-z0-9._-]{1,64}')

SCHEMA = '''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    firstname TEXT,
    lastname TEXT,
    middlename TEXT,
    password TEXT,
    active BOOLEAN NOT NULL DEFAULT 1,
    is_admin BOOLEAN NOT NULL DEFAULT 0,
    session_version INTEGER NOT NULL DEFAULT 0
)
'''

# columns added after the first release, for tables created before them
ADDED_COLUMNS = (
    ('is_admin', 'BOOLEAN NOT NULL DEFAULT 0'),
    ('session_version', 'INTEGER NOT NULL DEFAULT 0'),
)


class ConfigError(Exception):
    """Sign-in is misconfigured, webssh can not start."""


def is_yes(value):
    # hand-edited rows may hold 'false' or 'no': anything but an explicit
    # yes counts as no
    return str(value).strip().lower() in ('1', 'true')


class User(object):

    def __init__(self, row):
        self.id = row['id']
        self.username = row['username']
        self.firstname = row['firstname']
        self.lastname = row['lastname']
        self.middlename = row['middlename']
        self.password = row['password']
        self.active = is_yes(row['active'])
        self.is_admin = is_yes(row['is_admin'])
        self.session_version = row['session_version']
        self.fullname = ' '.join(
            filter(None, [self.lastname, self.firstname, self.middlename])
        ) or self.username


def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def username_error(username):
    if not USERNAME_RE.fullmatch(username):
        return ('Username must be 1 to 64 Latin letters, digits, '
                'dots, underscores or dashes')
    return None


def password_error(password, repeated):
    if len(password) < MIN_PASSWORD_LENGTH:
        return 'Password must be at least {} characters'.format(
            MIN_PASSWORD_LENGTH)
    if len(password.encode()) > MAX_PASSWORD_BYTES:
        return 'Password must be at most {} bytes'.format(MAX_PASSWORD_BYTES)
    if password != repeated:
        return 'Passwords do not match'
    return None


class UserStore(object):

    def __init__(self, path):
        self.path = path
        try:
            self.conn = sqlite3.connect(path)
            self.conn.row_factory = sqlite3.Row
            with self.conn:
                self.conn.execute(SCHEMA)
                self.add_missing_columns()
        except sqlite3.Error as exc:
            raise ConfigError('Can not open {!r}: {}'.format(path, exc))

    def add_missing_columns(self):
        existing = {row['name'] for row in
                    self.conn.execute('PRAGMA table_info(users)')}
        for name, definition in ADDED_COLUMNS:
            if name not in existing:
                self.conn.execute('ALTER TABLE users ADD COLUMN {} {}'
                                  .format(name, definition))

    def is_empty(self):
        return self.conn.execute('SELECT 1 FROM users LIMIT 1').fetchone() \
            is None

    def add(self, username, password, is_admin=False):
        with self.conn:
            self.conn.execute(
                'INSERT INTO users (username, password, is_admin) '
                'VALUES (?, ?, ?)',
                (username, hash_password(password), int(is_admin))
            )

    def create(self, username, password_hash, is_admin=False,
               firstname=None, lastname=None, middlename=None):
        with self.conn:
            self.conn.execute(
                'INSERT INTO users (username, password, is_admin, firstname, '
                'lastname, middlename) VALUES (?, ?, ?, ?, ?, ?)',
                (username, password_hash, int(is_admin), firstname or None,
                 lastname or None, middlename or None)
            )

    def update_names(self, user_id, firstname, lastname, middlename):
        with self.conn:
            self.conn.execute(
                'UPDATE users SET firstname = ?, lastname = ?, '
                'middlename = ? WHERE id = ?',
                (firstname or None, lastname or None, middlename or None,
                 user_id)
            )

    def set_password(self, user_id, password_hash):
        """Also ends every session of the user (ADR 0002)."""
        with self.conn:
            self.conn.execute(
                'UPDATE users SET password = ?, '
                'session_version = session_version + 1 WHERE id = ?',
                (password_hash, user_id)
            )

    def end_sessions(self, user_id):
        with self.conn:
            self.conn.execute(
                'UPDATE users SET session_version = session_version + 1 '
                'WHERE id = ?', (user_id,)
            )

    def set_active(self, user_id, active):
        with self.conn:
            self.conn.execute('UPDATE users SET active = ? WHERE id = ?',
                              (int(active), user_id))

    def set_admin(self, user_id, is_admin):
        with self.conn:
            self.conn.execute('UPDATE users SET is_admin = ? WHERE id = ?',
                              (int(is_admin), user_id))

    def is_username_taken(self, username):
        return self.conn.execute(
            'SELECT 1 FROM users WHERE lower(username) = lower(?)',
            (username,)
        ).fetchone() is not None

    def _find_by(self, column, value):
        row = self.conn.execute(
            'SELECT * FROM users WHERE {} = ?'.format(column), (value,)
        ).fetchone()
        return User(row) if row else None

    def list(self):
        return [User(row) for row in
                self.conn.execute('SELECT * FROM users ORDER BY username')]

    def ensure_administrator(self):
        """Makes the oldest active user an Administrator if there is none.

        Databases created before administration existed have none.
        """
        active = sorted((u for u in self.list() if u.active),
                        key=lambda u: u.id)
        if not active or any(u.is_admin for u in active):
            return
        with self.conn:
            self.conn.execute('UPDATE users SET is_admin = 1 WHERE id = ?',
                              (active[0].id,))
        logging.warning('No active administrator, made {!r} one'
                        .format(active[0].username))

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
            self.ensure_administrator()
            return

        if not username or not password:
            raise ConfigError(
                'No users in {!r} and WSSH_INIT_USER/WSSH_INIT_PASSWORD '
                'not set'.format(self.path)
            )
        if len(password.encode()) > MAX_PASSWORD_BYTES:
            raise ConfigError('WSSH_INIT_PASSWORD must be at most {} bytes'
                              .format(MAX_PASSWORD_BYTES))
        self.add(username, password, is_admin=True)
        logging.info('Created administrator {!r}'.format(username))


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

    The id and the user's session_version (ADR 0002): everything else is
    read from the DB, so edits there take effect at once, and bumping the
    version ends every session of that user.
    """

    def __init__(self, user_id, version, last_activity):
        self.user_id = user_id
        self.version = version
        self.last_activity = last_activity

    @classmethod
    def for_user(cls, user):
        return cls(user.id, user.session_version, time.time())

    @classmethod
    def from_json(cls, value):
        try:
            data = json.loads(value)
            session = cls(data['user_id'], int(data['version']),
                          float(data['last_activity']))
        except (ValueError, TypeError, KeyError):
            return None
        return session if session.user_id else None

    def to_json(self):
        return json.dumps(dict(user_id=self.user_id, version=self.version,
                               last_activity=self.last_activity))

    def belongs_to(self, user):
        return self.version == user.session_version

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
