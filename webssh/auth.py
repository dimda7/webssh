import logging
import sqlite3
import time

from collections import defaultdict, deque

import bcrypt


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


class User(object):

    def __init__(self, id, username, firstname, lastname, middlename,
                 password, active):
        self.id = id
        self.username = username
        self.password = password
        self.active = bool(active)
        self.fullname = ' '.join(
            filter(None, [lastname, firstname, middlename])
        ) or username


def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


class UserStore(object):

    def __init__(self, path):
        self.path = path
        self.conn = sqlite3.connect(path)
        with self.conn:
            self.conn.execute(SCHEMA)

    def is_empty(self):
        return self.conn.execute('SELECT 1 FROM users LIMIT 1').fetchone() \
            is None

    def add(self, username, password):
        with self.conn:
            self.conn.execute(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                (username, hash_password(password))
            )

    def find(self, username):
        row = self.conn.execute(
            'SELECT id, username, firstname, lastname, middlename, password, '
            'active FROM users WHERE username = ?', (username,)
        ).fetchone()
        return User(*row) if row else None

    def bootstrap(self, username, password):
        """Creates the first user, if the table is empty."""
        if not self.is_empty():
            if username or password:
                logging.warning(
                    'users table is not empty, WSSH_INIT_* ignored'
                )
            return

        if not username or not password:
            raise ValueError(
                'No users in {!r} and WSSH_INIT_USER/WSSH_INIT_PASSWORD '
                'not set'.format(self.path)
            )
        self.add(username, password)
        logging.info('Created user {!r}'.format(username))


# checked against when there is no such user, so that the response time
# does not tell which usernames exist
DUMMY_HASH = hash_password('webssh-dummy-password')


def authenticate(user_store, username, password):
    """Returns the active user with this username and password, or None."""
    user = user_store.find(username)
    hashed = user.password if user and user.password else DUMMY_HASH
    matched = bcrypt.checkpw(password.encode(), hashed.encode())
    if user and user.password and user.active and matched:
        return user
    return None


class SignInLimiter(object):
    """Counts failed sign-ins per client IP within a sliding window."""

    def __init__(self, limit=5, window=300):
        self.limit = limit
        self.window = window
        self.failures = defaultdict(deque)

    def _recent(self, ip):
        failures = self.failures[ip]
        threshold = time.time() - self.window
        while failures and failures[0] < threshold:
            failures.popleft()
        if not failures:
            del self.failures[ip]
        return failures

    def is_blocked(self, ip):
        return len(self._recent(ip)) >= self.limit

    def add_failure(self, ip):
        self.failures[ip].append(time.time())
