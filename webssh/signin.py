import functools
import json
import logging
import re
import sqlite3
import time

from collections import deque
from concurrent.futures import ThreadPoolExecutor

import bcrypt

import tornado.gen

from tornado.process import cpu_count


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


class Names(object):
    """A User's first, last and middle name, any of them may be missing."""

    fields = ('firstname', 'lastname', 'middlename')

    def __init__(self, firstname=None, lastname=None, middlename=None):
        self.firstname = firstname or None
        self.lastname = lastname or None
        self.middlename = middlename or None

    def values(self):
        return tuple(getattr(self, field) for field in self.fields)

    def full(self):
        return ' '.join(filter(None, [self.lastname, self.firstname,
                                      self.middlename]))


class User(object):

    def __init__(self, row):
        self.id = row['id']
        self.username = row['username']
        self.names = Names(*(row[field] for field in Names.fields))
        self.password = row['password']
        self.active = is_yes(row['active'])
        self.is_administrator = is_yes(row['is_admin'])
        self.session_version = row['session_version']
        self.fullname = self.names.full() or self.username


class UsernameTaken(Exception):
    """Another User already has this username, in any letter case."""


class LastAdministrator(Exception):
    """The change would leave no active Administrator."""


class UserGone(Exception):
    """The User was removed from the DB, by hand or by another writer."""


class TooManyAttempts(Exception):
    """Too many recent password attempts under the same limiter key."""


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


# the same reading of hand-edited values as is_yes()
SQL_YES = "lower(trim({})) IN ('1', 'true')"
ACTIVE_ADMINISTRATOR = '({} AND {})'.format(
    SQL_YES.format('is_admin'), SQL_YES.format('active'))


class UserStore(object):

    def __init__(self, path):
        self.path = path
        try:
            self.conn = sqlite3.connect(path)
            self.conn.row_factory = sqlite3.Row
            with self.conn:
                self.conn.execute(SCHEMA)
                self.upgrade_schema()
        except sqlite3.Error as exc:
            raise ConfigError('Can not open {!r}: {}'.format(path, exc))

    def upgrade_schema(self):
        existing = {row['name'] for row in
                    self.conn.execute('PRAGMA table_info(users)')}
        for name, definition in ADDED_COLUMNS:
            if name not in existing:
                self.conn.execute('ALTER TABLE users ADD COLUMN {} {}'
                                  .format(name, definition))
        try:
            self.conn.execute(
                'CREATE UNIQUE INDEX IF NOT EXISTS users_username_any_case '
                'ON users (lower(username))'
            )
        except sqlite3.IntegrityError:
            logging.warning('Some usernames in {!r} differ only in letter '
                            'case; rename them so they stay unique'
                            .format(self.path))

    def is_empty(self):
        return self.conn.execute('SELECT 1 FROM users LIMIT 1').fetchone() \
            is None

    def create(self, username, password_hash, is_administrator=False,
               names=None):
        names = names or Names()
        try:
            with self.conn:
                self.conn.execute(
                    'INSERT INTO users (username, password, is_admin, '
                    'firstname, lastname, middlename) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (username, password_hash, int(is_administrator))
                    + names.values()
                )
        except sqlite3.IntegrityError as exc:
            if 'UNIQUE' not in str(exc):
                raise
            raise UsernameTaken(username)

    def is_username_taken(self, username):
        return self.conn.execute(
            'SELECT 1 FROM users WHERE lower(username) = lower(?)',
            (username,)
        ).fetchone() is not None

    def _update(self, user_id, sql, params=()):
        with self.conn:
            changed = self.conn.execute(sql, params + (user_id,)).rowcount
        if not changed:
            raise UserGone(user_id)

    def update_names(self, user_id, names):
        self._update(user_id, 'UPDATE users SET firstname = ?, lastname = ?, '
                     'middlename = ? WHERE id = ?', names.values())

    def set_password(self, user_id, password_hash):
        """Also ends every session of the user (ADR 0002)."""
        self._update(user_id, 'UPDATE users SET password = ?, '
                     'session_version = session_version + 1 WHERE id = ?',
                     (password_hash,))

    def end_sessions(self, user_id):
        with self.conn:
            self.conn.execute(
                'UPDATE users SET session_version = session_version + 1 '
                'WHERE id = ?', (user_id,)
            )

    def _set_flag(self, column, user_id, value, also=''):
        """Sets active or is_admin, keeping an active Administrator.

        Turning a flag off is one statement that also checks another
        active Administrator remains, so that it holds even with other
        writers on the same DB file. `also` adds more assignments.
        """
        with self.conn:
            if value:
                changed = self.conn.execute(
                    'UPDATE users SET {} = 1{} WHERE id = ?'.format(
                        column, also), (user_id,)
                ).rowcount
            else:
                changed = self.conn.execute(
                    'UPDATE users SET {column} = 0{also} WHERE id = ? AND '
                    '(NOT {active_admin} OR EXISTS (SELECT 1 FROM users '
                    'WHERE id != ? AND {active_admin}))'.format(
                        column=column, also=also,
                        active_admin=ACTIVE_ADMINISTRATOR),
                    (user_id, user_id)
                ).rowcount
        if not changed:
            if not self.find_by_id(user_id):
                raise UserGone(user_id)
            raise LastAdministrator()

    def set_active(self, user_id, active):
        # deactivation ends the sessions too, so that reactivating does not
        # bring old cookies back
        also = '' if active else ', session_version = session_version + 1'
        self._set_flag('active', user_id, active, also)

    def set_administrator(self, user_id, is_administrator):
        self._set_flag('is_admin', user_id, is_administrator)

    def _find_by(self, column, value):
        row = self.conn.execute(
            'SELECT * FROM users WHERE {} = ?'.format(column), (value,)
        ).fetchone()
        return User(row) if row else None

    def find(self, username):
        return self._find_by('username', username)

    def find_by_id(self, user_id):
        return self._find_by('id', user_id)

    def list(self):
        return [User(row) for row in
                self.conn.execute('SELECT * FROM users ORDER BY username')]

    def ensure_administrator(self):
        """Makes the oldest active user an Administrator if there is none.

        Databases created before administration existed have none.
        """
        active = sorted((u for u in self.list() if u.active),
                        key=lambda u: u.id)
        if not active or any(u.is_administrator for u in active):
            return
        self.set_administrator(active[0].id, True)
        logging.warning('No active administrator, made {!r} one'
                        .format(active[0].username))

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
        # the same rules as for users created on the users page
        error = username_error(username)
        if error:
            raise ConfigError('WSSH_INIT_USER: ' + error)
        error = password_error(password, password)
        if error:
            raise ConfigError('WSSH_INIT_PASSWORD: ' + error)
        self.create(username, hash_password(password), is_administrator=True)
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


# bcrypt is slow on purpose: never run it on the IOLoop
password_executor = ThreadPoolExecutor(max_workers=cpu_count())


def hash_password_off_loop(password):
    return password_executor.submit(hash_password, password)


def check_password_off_loop(user, password):
    return password_executor.submit(check_password, user, password)


@tornado.gen.coroutine
def check_password_limited(limiter, key, username, user, password):
    """check_password_off_loop() counted against the limiter under key.

    Raises TooManyAttempts when the key is over the limit.
    """
    if limiter.is_blocked(key):
        raise TooManyAttempts()
    # counted before bcrypt runs, so concurrent attempts can not slip past
    # the limit while earlier ones are still being checked
    limiter.add_attempt(key, username)
    matched = yield check_password_off_loop(user, password)
    if matched:
        limiter.forget(key, username)
    return matched


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
            # cookies from before session_version existed carry none;
            # every user started at 0
            session = cls(data['user_id'], int(data.get('version', 0)),
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
    """Counts password attempts per key within a sliding window.

    The key is the client IP for sign-in, and the User for checking the
    current password in My profile. An attempt counts from the moment it
    starts; a successful one is forgotten, together with earlier failures
    for the same username only.
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
