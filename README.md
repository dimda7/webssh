## WebSSH

[![python](https://github.com/dimda7/webssh/actions/workflows/python.yml/badge.svg)](https://github.com/dimda7/webssh/actions/workflows/python.yml)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/webssh.svg)

> Форк [huashengdun/webssh](https://github.com/huashengdun/webssh) с входом в webssh по имени пользователя и паролю, несколькими доработками клиента и готовой настройкой HTTPS для Docker. Подробнее — в разделе [Изменения форка](#изменения-форка).


### Введение

Простое веб-приложение — SSH-клиент для подключения к вашим SSH-серверам. Написано на Python с использованием tornado, paramiko и xterm.js.

### Возможности

* Аутентификация по паролю, в том числе с пустым паролем.
* Аутентификация по публичному ключу: поддерживаются ключи DSA, RSA, ECDSA и Ed25519.
* Поддержка зашифрованных ключей.
* Двухфакторная аутентификация (одноразовые пароли TOTP).
* Полноэкранный режим терминала.
* Изменяемый размер окна терминала.
* Автоматическое определение кодировки SSH-сервера по умолчанию.
* Поддержка современных браузеров: Chrome, Firefox, Safari, Edge, Opera.


### Изменения форка

* **Запоминание приватного ключа.** После успешного входа файл приватного ключа (и пароль к нему, если он есть) сохраняется в `localStorage` браузера и при следующем открытии подставляется в форму. Сброс формы удаляет сохранённый ключ. Используйте это только на доверенном устройстве.
* **Копирование при выделении.** Выделенный в терминале текст сразу копируется в буфер обмена.
* **Буфер обмена через OSC 52.** Удалённые программы (tmux, vim и т. п.) могут записывать в буфер обмена браузера с помощью escape-последовательности OSC 52. Читать буфер обмена со стороны сервера нельзя.
* **HTTPS в Docker.** `docker-compose.yml` поднимает только HTTPS на порту `4433` с сертификатами из локальной папки `certs/` (см. [Запуск в Docker](#запуск-в-docker)).
* **Вход в webssh.** С опцией `--authdb` webssh перед формой Connect требует войти по имени пользователя и паролю; пользователи хранятся в SQLite. Администраторы управляют пользователями прямо в webssh (см. [Вход в webssh](#вход-в-webssh)).


### Скриншоты

![Вход](preview/login.png)
![Терминал](preview/terminal.png)


### Как это работает
```
+---------+     http     +--------+    ssh    +-----------+
| browser | <==========> | webssh | <=======> | ssh server|
+---------+   websocket  +--------+    ssh    +-----------+
```

### Требования

* Python 3.10+


### Быстрый старт

1. Установите приложение: `pip install git+https://github.com/dimda7/webssh.git` (`pip install webssh` установит оригинальную версию без изменений форка)
2. Запустите веб-сервер командой `wssh`
3. Откройте в браузере `127.0.0.1:8888`
4. Заполните форму и нажмите «Connect».


### Параметры сервера

```bash
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

# включить вход в webssh (см. «Вход в webssh»)
wssh --authdb=/path/to/users.db --cookiesecret=<hex>

# остальные параметры
wssh --help
```

### Консоль браузера

```javascript
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
```

### Свой шрифт

Чтобы использовать свой шрифт, положите файл шрифта в папку `webssh/static/css/fonts/` и перезапустите сервер.

### Параметры в URL

Параметры можно передавать через URL (в query или во fragment), например:

Данные формы (пароль должен быть закодирован в base64, приватный ключ так передать нельзя)
```bash
http://localhost:8888/?hostname=xx&username=yy&password=str_base64_encoded
```

Цвет фона терминала
```bash
http://localhost:8888/#bgcolor=green
```

Цвет шрифта терминала
```bash
http://localhost:8888/#fontcolor=red
```

Свой заголовок страницы
```bash
http://localhost:8888/?title=my-ssh-server
```

Кодировка
```bash
http://localhost:8888/#encoding=gbk
```

Размер шрифта
```bash
http://localhost:8888/#fontsize=24
```

Команда, которая выполнится сразу после входа
```bash
http://localhost:8888/?command=pwd
```

Тип терминала
```bash
http://localhost:8888/?term=xterm-256color
```

### Вход в webssh

По умолчанию webssh открыт всем, кто может открыть его в браузере. С опцией `--authdb=/path/to/users.db` перед формой Connect нужно войти по имени пользователя и паролю. Пользователи хранятся в этом файле SQLite, таблица создаётся автоматически.

* `--cookiesecret` или переменная `WSSH_COOKIE_SECRET` — секрет подписи cookie сессии, 32 байта в hex (`python -c "import secrets; print(secrets.token_hex(32))"`). Без него webssh не стартует.
* `WSSH_INIT_USER` и `WSSH_INIT_PASSWORD` — первый пользователь, он же первый администратор. Создаётся только при первом запуске, пока таблица пустая; дальше эти переменные игнорируются (в лог пишется предупреждение). Если таблица пустая, а переменных нет, webssh не стартует.
* `--authtimeout` — через сколько секунд бездействия нужно войти заново (по умолчанию 3600). Уже открытые терминалы при этом не обрываются.
* Над формой Connect — имя пользователя и ссылки Account, Users (только для администраторов) и Sign out. Cookie сессии живёт до закрытия браузера.
* После входа webssh возвращает на страницу, которая его потребовала, вместе с [параметрами в URL](#параметры-в-url).
* После 5 неудачных попыток входа за 5 минут с одного IP вход временно блокируется. IP берётся из заголовков `X-Real-Ip`/`X-Forwarded-For`, если включён `--xheaders` (по умолчанию включён). Если перед webssh нет обратного прокси, который сам выставляет эти заголовки, запускайте с `--xheaders=False`: иначе клиент подставит в заголовок любой IP и обойдёт ограничение. В `docker-compose.yml` так и сделано.

#### Управление пользователями

Администратор открывает **Users** (`/admin/users`): там список пользователей и форма создания нового. На странице пользователя можно поменять имя, задать новый пароль, отключить или снова включить пользователя и выдать или снять права администратора. Удалять пользователей нельзя — только отключать.

* Имя пользователя — латиница, цифры и `.`, `_`, `-`, от 1 до 64 символов; `Bob` нельзя завести, если уже есть `bob`. После создания имя не меняется.
* Пароль — не короче 8 символов и не длиннее 72 байт (ограничение bcrypt; кириллица занимает 2 байта на символ).
* Новый пароль, заданный администратором, завершает все сессии этого пользователя. Отключённый пользователь теряет доступ на следующем же запросе; уже открытые терминалы продолжают работать.
* Администратор не может отключить себя или снять с себя права, поэтому хотя бы один активный администратор остаётся всегда.
* Все действия записываются в лог webssh (кто, что и над кем), пароли в лог не попадают.

Каждый пользователь на странице **Account** (`/account`) может сменить свой пароль, введя текущий: в этом браузере он остаётся в webssh, а все остальные его сессии завершаются. Кнопка **Sign out everywhere** завершает все сессии, включая текущую.

При обновлении с версии без администраторов webssh сам добавит в базу нужные колонки и сделает администратором самого старого активного пользователя (в лог пишется, кого именно).

#### Аварийный доступ

Если доступ к админке потерян (например, базу правили вручную), пользователей можно менять прямо в базе. Команды запускаются там, где установлен webssh (нужен `bcrypt`); в Docker — через `docker-compose exec web` и с путём `/data/users.db`. Пароль в командной строке попадает в историю shell, поэтому её стоит потом почистить.

Сделать пользователя администратором и включить его
```bash
python -c "import sqlite3, sys; db, user = sys.argv[1:]; c = sqlite3.connect(db); c.execute('UPDATE users SET is_admin = 1, active = 1 WHERE username = ?', (user,)); c.commit()" users.db alice
```

Задать пароль (заодно завершает все сессии пользователя)
```bash
python -c "import bcrypt, sqlite3, sys; db, user, pw = sys.argv[1:]; c = sqlite3.connect(db); c.execute('UPDATE users SET password = ?, session_version = session_version + 1 WHERE username = ?', (bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode(), user)); c.commit()" users.db alice 'новый пароль'
```

В поле `password` должен лежать bcrypt-хэш, а не сам пароль: пользователь с паролем открытым текстом войти не сможет.

### Запуск в Docker

Compose-файл ожидает сертификат и ключ в папке `certs/` (она исключена из git и из Docker-образа). Самоподписанный сертификат можно создать так:
```
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/webssh.key -out certs/webssh.crt -subj "/CN=localhost"
```

Скопируйте `.env.example` в `.env` и заполните `WSSH_COOKIE_SECRET`, `WSSH_INIT_USER` и `WSSH_INIT_PASSWORD` (`.env` исключён из git). База пользователей хранится в Docker-томе `webssh-data`.

Запустите приложение и откройте `https://localhost:4433`. Наружу открыт только HTTPS: порт обычного http `8888` в `docker-compose.yml` не пробрасывается, чтобы пароль входа не передавался открытым текстом.
```
docker-compose up
```

Остановить приложение
```
docker-compose down
```

### Тесты

Зависимости
```
pip install pytest pytest-cov flake8 -r requirements.txt
```

Запуск всех тестов через unittest
```
python -m unittest discover tests
```

Запуск всех тестов через pytest
```
python -m pytest tests
```

### Развёртывание

За сервером Nginx

```bash
wssh --address='127.0.0.1' --port=8888 --policy=reject
```

С включённым входом в webssh добавьте `--tdstream=127.0.0.1`: тогда webssh принимает запросы только от Nginx, и IP клиента для ограничения попыток входа берётся из заголовков, которые выставляет Nginx.
```bash
wssh --address='127.0.0.1' --port=8888 --policy=reject --tdstream=127.0.0.1 --authdb=/path/to/users.db
```
```nginx
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
```

Как самостоятельный сервер
```bash
wssh --port=8080 --sslport=4433 --certfile='cert.crt' --keyfile='cert.key' --xheaders=False --policy=reject
```


### Советы

* Какой бы способ развёртывания вы ни выбрали, не забудьте включить SSL.
* По умолчанию обычные http-запросы из публичной сети либо перенаправляются, либо блокируются; перенаправление имеет приоритет над блокировкой.
* Старайтесь использовать политику reject для неизвестных ключей хоста вместе с проверенным known_hosts — это защищает от атак «человек посередине». Приложение по очереди проверяет системный файл ключей хостов (`~/.ssh/known_hosts`) и файл ключей приложения (`./known_hosts`); если имя SSH-сервера не найдено или ключ не совпадает, подключение прерывается.
