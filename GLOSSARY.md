# WebSSH

A web application that lets a person open an SSH terminal to a remote host from the browser.

## Language

**User**:
A person who has an account in webssh and can sign in to it. The username on a remote host is not a User; it is part of SSH credentials.
_Avoid_: account, web user

**Administrator**:
A User who may manage other Users: create them, set their passwords, deactivate them and grant or revoke administration.
_Avoid_: admin, superuser, root (root is a user on a remote host)

**Deactivated User**:
A User who can no longer sign in and whose sessions stop working; the User is kept, never deleted, and can be reactivated.
_Avoid_: deleted, blocked, banned (being temporarily refused after too many failed sign-ins is not deactivation)

**SSH credentials**:
The hostname, port, username, password, private key and TOTP code used to authenticate on a remote SSH host.
_Avoid_: login, user

**Sign-in**:
Proving who you are to webssh itself, before any remote host is involved.
_Avoid_: login, auth

**Connect**:
Opening an SSH session to a remote host using SSH credentials.
_Avoid_: login, sign-in
