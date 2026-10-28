import sqlite3


# The password, private key and passphrase are stored in plaintext for now;
# encrypting them with a key from .env is the next step (ADR 0003).
SCHEMA = '''
CREATE TABLE IF NOT EXISTS saved_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users (id),
    name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL,
    username TEXT NOT NULL,
    password TEXT,
    privatekey TEXT,
    passphrase TEXT,
    UNIQUE (user_id, name),
    CHECK ((password IS NULL) != (privatekey IS NULL))
)
'''


class NameTaken(Exception):
    """The User already has a Saved Host with this name."""


class SavedHostGone(Exception):
    """No such Saved Host among the User's own."""


class SavedHost(object):

    def __init__(self, row):
        self.id = row['id']
        self.name = row['name']
        self.hostname = row['hostname']
        self.port = row['port']
        self.username = row['username']
        self.password = row['password']
        self.privatekey = row['privatekey']
        self.passphrase = row['passphrase']

    @property
    def has_key(self):
        return self.privatekey is not None


class SavedHostStore(object):
    """The Saved Hosts of each User; every call names the owning User."""

    def __init__(self, conn):
        self.conn = conn
        with self.conn:
            self.conn.execute(SCHEMA)

    def list(self, user_id):
        return [SavedHost(row) for row in self.conn.execute(
            'SELECT * FROM saved_hosts WHERE user_id = ? '
            'ORDER BY lower(name), name', (user_id,))]

    def find(self, user_id, host_id):
        row = self.conn.execute(
            'SELECT * FROM saved_hosts WHERE id = ? AND user_id = ?',
            (host_id, user_id)
        ).fetchone()
        if not row:
            raise SavedHostGone(host_id)
        return SavedHost(row)

    def is_name_taken(self, user_id, name, except_id=None):
        return self.conn.execute(
            'SELECT 1 FROM saved_hosts WHERE user_id = ? AND name = ? '
            'AND id IS NOT ?', (user_id, name, except_id)
        ).fetchone() is not None

    def _write(self, sql, params):
        try:
            with self.conn:
                return self.conn.execute(sql, params).rowcount
        except sqlite3.IntegrityError as exc:
            if 'UNIQUE' not in str(exc):
                raise
            raise NameTaken()

    def create(self, user_id, name, hostname, port, username, password=None,
               privatekey=None, passphrase=None):
        """Either password or privatekey, with an optional passphrase."""
        self._write(
            'INSERT INTO saved_hosts (user_id, name, hostname, port, '
            'username, password, privatekey, passphrase) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (user_id, name, hostname, port, username, password, privatekey,
             passphrase)
        )

    def _change(self, user_id, host_id, sql, params=()):
        changed = self._write(sql + ' WHERE id = ? AND user_id = ?',
                              params + (host_id, user_id))
        if not changed:
            raise SavedHostGone(host_id)

    def update_details(self, user_id, host_id, name, hostname, port,
                       username):
        self._change(user_id, host_id, 'UPDATE saved_hosts SET name = ?, '
                     'hostname = ?, port = ?, username = ?',
                     (name, hostname, port, username))

    def set_password(self, user_id, host_id, password):
        """Replaces the secret, a private key included."""
        self._change(user_id, host_id, 'UPDATE saved_hosts SET password = ?, '
                     'privatekey = NULL, passphrase = NULL', (password,))

    def set_key(self, user_id, host_id, privatekey, passphrase=None):
        """Replaces the secret, a password included."""
        self._change(user_id, host_id, 'UPDATE saved_hosts SET password = '
                     'NULL, privatekey = ?, passphrase = ?',
                     (privatekey, passphrase))

    def delete(self, user_id, host_id):
        self._change(user_id, host_id, 'DELETE FROM saved_hosts')
