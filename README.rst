WebSSH
------

|PyPI - Python Version|

    Форк `huashengdun/webssh <https://github.com/huashengdun/webssh>`_
    с несколькими доработками клиента и готовой настройкой HTTPS для
    Docker. Подробнее — в разделе `Изменения форка`_.

Введение
~~~~~~~~

Простое веб-приложение — SSH-клиент для подключения к вашим
SSH-серверам. Написано на Python с использованием tornado, paramiko и
xterm.js.

Возможности
~~~~~~~~~~~

-  Аутентификация по паролю, в том числе с пустым паролем.
-  Аутентификация по публичному ключу: поддерживаются ключи DSA, RSA,
   ECDSA и Ed25519.
-  Поддержка зашифрованных ключей.
-  Двухфакторная аутентификация (одноразовые пароли TOTP).
-  Полноэкранный режим терминала.
-  Изменяемый размер окна терминала.
-  Автоматическое определение кодировки SSH-сервера по умолчанию.
-  Поддержка современных браузеров: Chrome, Firefox, Safari, Edge,
   Opera.

Изменения форка
~~~~~~~~~~~~~~~

-  **Запоминание приватного ключа.** После успешного входа файл
   приватного ключа (и пароль к нему, если он есть) сохраняется в
   ``localStorage`` браузера и при следующем открытии подставляется в
   форму. Сброс формы удаляет сохранённый ключ. Используйте это только
   на доверенном устройстве.
-  **Копирование при выделении.** Выделенный в терминале текст сразу
   копируется в буфер обмена.
-  **Буфер обмена через OSC 52.** Удалённые программы (tmux, vim и т. п.)
   могут записывать в буфер обмена браузера с помощью
   escape-последовательности OSC 52. Читать буфер обмена со стороны
   сервера нельзя.
-  **HTTPS в Docker.** ``docker-compose.yml`` поднимает HTTPS на порту
   ``4433`` с сертификатами из локальной папки ``certs/`` (см.
   `Запуск в Docker`_).

Скриншоты
~~~~~~~~~

|Login| |Terminal|

Как это работает
~~~~~~~~~~~~~~~~

::

    +---------+     http     +--------+    ssh    +-----------+
    | browser | <==========> | webssh | <=======> | ssh server|
    +---------+   websocket  +--------+    ssh    +-----------+

Требования
~~~~~~~~~~

-  Python 3.10+

Быстрый старт
~~~~~~~~~~~~~

1. Установите приложение:
   ``pip install git+https://github.com/dimda7/webssh.git``
   (``pip install webssh`` установит оригинальную версию без изменений
   форка)
2. Запустите веб-сервер командой ``wssh``
3. Откройте в браузере ``127.0.0.1:8888``
4. Заполните форму и нажмите «Connect».

Параметры сервера
~~~~~~~~~~~~~~~~~

.. code:: bash

    # запустить http-сервер на заданном адресе и порту
    wssh --address='2.2.2.2' --port=8000

    # запустить https-сервер, certfile и keyfile обязательны
    wssh --certfile='/path/to/cert.crt' --keyfile='/path/to/cert.key'

    # политика для неизвестных ключей хоста
    wssh --policy=reject

    # уровень логирования
    wssh --logging=debug

    # писать лог в файл
    wssh --log-file-prefix=main.log

    # остальные параметры
    wssh --help

Консоль браузера
~~~~~~~~~~~~~~~~

.. code:: javascript

    // подключиться к SSH-серверу
    wssh.connect(hostname, port, username, password, privatekey, passphrase, totp);

    // передать в wssh.connect объект
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

    // без аргументов wssh подключится по данным из формы
    wssh.connect();

    // задать клиенту новую кодировку
    wssh.set_encoding(encoding);

    // вернуть кодировку по умолчанию
    wssh.reset_encoding();

    // отправить команду на сервер
    wssh.send('ls -l');

Свой шрифт
~~~~~~~~~~

Чтобы использовать свой шрифт, положите файл шрифта в папку
``webssh/static/css/fonts/`` и перезапустите сервер.

Параметры в URL
~~~~~~~~~~~~~~~

Параметры можно передавать через URL (в query или во fragment),
например:

Данные формы (пароль должен быть закодирован в base64, приватный ключ
так передать нельзя)

.. code:: bash

    http://localhost:8888/?hostname=xx&username=yy&password=str_base64_encoded

Цвет фона терминала

.. code:: bash

    http://localhost:8888/#bgcolor=green

Цвет шрифта терминала

.. code:: bash

    http://localhost:8888/#fontcolor=red

Свой заголовок страницы

.. code:: bash

    http://localhost:8888/?title=my-ssh-server

Кодировка

.. code:: bash

    http://localhost:8888/#encoding=gbk

Размер шрифта

.. code:: bash

    http://localhost:8888/#fontsize=24

Команда, которая выполнится сразу после входа

.. code:: bash

    http://localhost:8888/?command=pwd

Тип терминала

.. code:: bash

    http://localhost:8888/?term=xterm-256color

Запуск в Docker
~~~~~~~~~~~~~~~

Compose-файл ожидает сертификат и ключ в папке ``certs/`` (она
исключена из git и из Docker-образа). Самоподписанный сертификат можно
создать так:

::

    mkdir -p certs
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
      -keyout certs/webssh.key -out certs/webssh.crt -subj "/CN=localhost"

Запустите приложение и откройте ``https://localhost:4433`` (обычный
http остаётся на порту ``8888``)

::

    docker-compose up

Остановить приложение

::

    docker-compose down

Тесты
~~~~~

Зависимости

::

    pip install pytest pytest-cov codecov flake8 mock

Запуск всех тестов через unittest

::

    python -m unittest discover tests

Запуск всех тестов через pytest

::

    python -m pytest tests

Развёртывание
~~~~~~~~~~~~~

За сервером Nginx

.. code:: bash

    wssh --address='127.0.0.1' --port=8888 --policy=reject

.. code:: nginx

    # пример конфигурации Nginx
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

Как самостоятельный сервер

.. code:: bash

    wssh --port=8080 --sslport=4433 --certfile='cert.crt' --keyfile='cert.key' --xheaders=False --policy=reject

Советы
~~~~~~

-  Какой бы способ развёртывания вы ни выбрали, не забудьте включить
   SSL.
-  По умолчанию обычные http-запросы из публичной сети либо
   перенаправляются, либо блокируются; перенаправление имеет приоритет
   над блокировкой.
-  Старайтесь использовать политику reject для неизвестных ключей хоста
   вместе с проверенным known_hosts — это защищает от атак «человек
   посередине». Приложение по очереди проверяет системный файл ключей
   хостов (``~/.ssh/known_hosts``) и файл ключей приложения
   (``./known_hosts``); если имя SSH-сервера не найдено или ключ не
   совпадает, подключение прерывается.

.. |PyPI - Python Version| image:: https://img.shields.io/pypi/pyversions/webssh.svg
.. |Login| image:: https://github.com/dimda7/webssh/raw/master/preview/login.png
.. |Terminal| image:: https://github.com/dimda7/webssh/raw/master/preview/terminal.png
