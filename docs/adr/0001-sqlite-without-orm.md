# Users in SQLite via the standard sqlite3 module, without an ORM

Sign-in needs one table and one lookup query per sign-in, so users are stored in SQLite through Python's built-in `sqlite3` with plain SQL. `docs/auth-recipe.md` uses async SQLAlchemy on PostgreSQL; we deliberately do not follow it here, because an async ORM adds dependencies and a session layer to a Tornado app that otherwise has no database at all. Revisit if the admin panel grows into real CRUD over several tables.
