WebSSH
------

|PyPI - Python Version|

    Fork of `huashengdun/webssh <https://github.com/huashengdun/webssh>`_
    with a few client-side additions and a ready-to-use HTTPS setup for
    Docker. See `Fork changes`_.

Introduction
~~~~~~~~~~~~

A simple web application to be used as an ssh client to connect to your
ssh servers. It is written in Python, base on tornado, paramiko and
xterm.js.

Features
~~~~~~~~

-  SSH password authentication supported, including empty password.
-  SSH public-key authentication supported, including DSA RSA ECDSA
   Ed25519 keys.
-  Encrypted keys supported.
-  Two-Factor Authentication (time-based one-time password) supported.
-  Fullscreen terminal supported.
-  Terminal window resizable.
-  Auto detect the ssh server's default encoding.
-  Modern browsers including Chrome, Firefox, Safari, Edge, Opera
   supported.

Fork changes
~~~~~~~~~~~~

-  **Remembered private key.** After a successful login the private key
   file (and its passphrase, if any) is saved in the browser's
   ``localStorage`` and restored into the form on the next visit.
   Resetting the form forgets it. Only use this on a device you trust.
-  **Copy on select.** Selecting text in the terminal copies it to the
   clipboard.
-  **OSC 52 clipboard.** Remote programs (tmux, vim, etc.) can set the
   browser clipboard through the OSC 52 escape sequence. Reading the
   clipboard from the server is not allowed.
-  **HTTPS in Docker.** ``docker-compose.yml`` serves HTTPS on port
   ``4433`` using certificates from the local ``certs/`` directory (see
   `Use Docker`_).

Preview
~~~~~~~

|Login| |Terminal|

How it works
~~~~~~~~~~~~

::

    +---------+     http     +--------+    ssh    +-----------+
    | browser | <==========> | webssh | <=======> | ssh server|
    +---------+   websocket  +--------+    ssh    +-----------+

Requirements
~~~~~~~~~~~~

-  Python 3.10+

Quickstart
~~~~~~~~~~

1. Install this app, run command
   ``pip install git+https://github.com/dimda7/webssh.git``
   (``pip install webssh`` installs the upstream version without the
   fork changes)
2. Start a webserver, run command ``wssh``
3. Open your browser, navigate to ``127.0.0.1:8888``
4. Input your data, submit the form.

Server options
~~~~~~~~~~~~~~

.. code:: bash

    # start a http server with specified listen address and listen port
    wssh --address='2.2.2.2' --port=8000

    # start a https server, certfile and keyfile must be passed
    wssh --certfile='/path/to/cert.crt' --keyfile='/path/to/cert.key'

    # missing host key policy
    wssh --policy=reject

    # logging level
    wssh --logging=debug

    # log to file
    wssh --log-file-prefix=main.log

    # more options
    wssh --help

Browser console
~~~~~~~~~~~~~~~

.. code:: javascript

    // connect to your ssh server
    wssh.connect(hostname, port, username, password, privatekey, passphrase, totp);

    // pass an object to wssh.connect
    var opts = {
      hostname: 'hostname',
      port: 'port',
      username: 'username',
      password: 'password',
      privatekey: 'the private key text',
      passphrase: 'passphrase',
      totp: 'totp'
    };
    wssh.connect(opts);

    // without an argument, wssh will use the form data to connect
    wssh.connect();

    // set a new encoding for client to use
    wssh.set_encoding(encoding);

    // reset encoding to use the default one
    wssh.reset_encoding();

    // send a command to the server
    wssh.send('ls -l');

Custom Font
~~~~~~~~~~~

To use custom font, put your font file in the directory
``webssh/static/css/fonts/`` and restart the server.

URL Arguments
~~~~~~~~~~~~~

Support passing arguments by url (query or fragment) like following
examples:

Passing form data (password must be encoded in base64, privatekey not
supported)

.. code:: bash

    http://localhost:8888/?hostname=xx&username=yy&password=str_base64_encoded

Passing a terminal background color

.. code:: bash

    http://localhost:8888/#bgcolor=green

Passing a user defined title

.. code:: bash

    http://localhost:8888/?title=my-ssh-server

Passing an encoding

.. code:: bash

    http://localhost:8888/#encoding=gbk

Passing a command executed right after login

.. code:: bash

    http://localhost:8888/?command=pwd

Passing a terminal type

.. code:: bash

    http://localhost:8888/?term=xterm-256color

Use Docker
~~~~~~~~~~

The compose file expects a certificate and key in ``certs/`` (the
directory is ignored by git and docker). For a self-signed one:

::

    mkdir -p certs
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
      -keyout certs/webssh.key -out certs/webssh.crt -subj "/CN=localhost"

Start up the app, then open ``https://localhost:4433`` (plain http stays
on port ``8888``)

::

    docker-compose up

Tear down the app

::

    docker-compose down

Tests
~~~~~

Requirements

::

    pip install pytest pytest-cov codecov flake8 mock

Use unittest to run all tests

::

    python -m unittest discover tests

Use pytest to run all tests

::

    python -m pytest tests

Deployment
~~~~~~~~~~

Running behind an Nginx server

.. code:: bash

    wssh --address='127.0.0.1' --port=8888 --policy=reject

.. code:: nginx

    # Nginx config example
    location / {
        proxy_pass http://127.0.0.1:8888;
        proxy_http_version 1.1;
        proxy_read_timeout 300;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Real-PORT $remote_port;
    }

Running as a standalone server

.. code:: bash

    wssh --port=8080 --sslport=4433 --certfile='cert.crt' --keyfile='cert.key' --xheaders=False --policy=reject

Tips
~~~~

-  For whatever deployment choice you choose, don't forget to enable
   SSL.
-  By default plain http requests from a public network will be either
   redirected or blocked and being redirected takes precedence over
   being blocked.
-  Try to use reject policy as the missing host key policy along with
   your verified known\_hosts, this will prevent man-in-the-middle
   attacks. The idea is that it checks the system host keys
   file("~/.ssh/known\_hosts") and the application host keys
   file("./known\_hosts") in order, if the ssh server's hostname is not
   found or the key is not matched, the connection will be aborted.

.. |PyPI - Python Version| image:: https://img.shields.io/pypi/pyversions/webssh.svg
.. |Login| image:: https://github.com/dimda7/webssh/raw/master/preview/login.png
.. |Terminal| image:: https://github.com/dimda7/webssh/raw/master/preview/terminal.png

