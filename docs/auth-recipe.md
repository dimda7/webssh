# Рецепт: аутентификация в Litestar-приложении (по образцу проекта grom/litestar)

Этот файл — инструкция для Claude Code: повторить в другом проекте ту же схему аутентификации.
Стек: Litestar 2.x, Jinja2 (SSR), SQLAlchemy async (PostgreSQL), bcrypt, cookie-сессии, CSRF.

## Общая схема

1. **Сессия** — клиентская, в зашифрованной cookie (`CookieBackendConfig`), секрет из `.env`.
2. **Логин** — HTML-форма `POST /auth/login` → поиск пользователя в таблице пользователей БД → проверка
   `bcrypt.checkpw` → запись `user_id` и пр. в `request.session` → `303` на `/`.
3. **Защита всех страниц** — собственный ASGI-middleware `AuthMiddleware` (не guards): пропускает
   статику и страницы логина, остальным без `user_id` в сессии отвечает редиректом на логин
   (или `401` JSON для `fetch`).
4. **Таймаут неактивности** — `last_activity` в сессии, обновляется на каждом запросе, 1 час.
5. **Logout** — `GET /auth/logout` → `request.clear_session()` → редирект на логин.
6. **CSRF** — встроенный `CSRFConfig`; формы шлют скрытое поле `_csrf_token`, `fetch()` берёт токен
   из `<meta name="csrf-token">`.
7. **JS-хелперы** (`static/js/api.js`) — понимают `401` от middleware и уводят на страницу логина.

Регистрации пользователей, ролей и восстановления пароля нет: пользователи и bcrypt-хэши уже лежат
в БД (в исходном проекте — таблица `fdw_users`), «Забыли пароль?» — просто модалка с e-mail админа.

## Зависимости

```
litestar>=2.0
bcrypt>=4.0
starlette>=0.36   # только ради JSONResponse/RedirectResponse в middleware
python-dotenv
sqlalchemy[asyncio], asyncpg
```

## 1. Секрет сессии (`.env` + `config.py`)

Секрет **хранится в `.env`**, никогда не генерируется при старте (иначе каждый рестарт разлогинивает
всех, а несколько воркеров получают разные секреты).

`.env.example`:
```
# Secret signing the session cookie and the CSRF token (see app.py).
# Generate with: python -c "import secrets; print(secrets.token_hex(32))"
SESSION_SECRET=
```

`config.py`:
```python
from dataclasses import dataclass, field
from os import environ

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    session_secret: bytes = field(default_factory=lambda: bytes.fromhex(environ["SESSION_SECRET"]))


settings = Settings()
```

`CookieBackendConfig` требует ключ ровно 16/24/32 байта — `token_hex(32)` даёт 32 байта.

## 2. Модель пользователя и схемы

```python
class User(Base):
    __tablename__ = "users"           # в исходнике: "fdw_users", schema="public"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str | None] = mapped_column(String, nullable=True)
    firstname: Mapped[str | None] = mapped_column(String, nullable=True)
    lastname: Mapped[str | None] = mapped_column(String, nullable=True)
    middlename: Mapped[str | None] = mapped_column(String, nullable=True)
    password: Mapped[str | None] = mapped_column(String, nullable=True)   # bcrypt hash
    active: Mapped[bool] = mapped_column(Boolean, default=True)
```

`schemas.py`:
```python
import msgspec


class LoginRequest(msgspec.Struct):
    username: str
    password: str
```

Сессия БД приходит через DI: `dependencies={"db_session": Provide(provide_db_session)}`, где
`provide_db_session` — async-генератор, отдающий `AsyncSession`.

## 3. Контроллер `controllers/auth.py`

```python
import time

import bcrypt
from litestar import Controller, get, post
from litestar.connection.request import Request
from litestar.enums import RequestEncodingType
from litestar.params import Body
from litestar.response import Redirect, Template
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import User
from schemas import LoginRequest


class AuthController(Controller):
    path = "/auth"

    @get("/login")
    async def login_page(self, request: Request) -> Template | Redirect:
        if request.session.get("user_id"):
            return Redirect("/")
        return Template(template_name="login.html", context={"error": None})

    @post("/login")
    async def login(
        self,
        request: Request,
        db_session: AsyncSession,
        data: LoginRequest = Body(media_type=RequestEncodingType.URL_ENCODED),
    ) -> Template | Redirect:
        username = data.username
        password = data.password

        if not username or not password:
            return Template(template_name="login.html", context={"error": "Введите логин и пароль"})

        result = await db_session.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()

        # One message for "no such user", "inactive" and "wrong password" — do not leak which.
        if not user or not user.active:
            return Template(template_name="login.html", context={"error": "Неверный логин или пароль"})
        if not user.password or not bcrypt.checkpw(password.encode(), user.password.encode()):
            return Template(template_name="login.html", context={"error": "Неверный логин или пароль"})

        request.session["user_id"] = user.id
        request.session["username"] = user.username or ""
        request.session["fullname"] = " ".join(
            filter(None, [user.lastname, user.firstname, user.middlename])
        ) or user.username or ""
        request.session["last_activity"] = time.time()

        return Redirect("/")

    @get("/logout")
    async def logout(self, request: Request) -> Redirect:
        request.clear_session()
        return Redirect("/auth/login")
```

Хэш для нового пользователя: `bcrypt.hashpw(b"password", bcrypt.gensalt()).decode()`.

## 4. Middleware `middleware.py`

Ключевые моменты:
- Чистый ASGI-класс, ставится в `middleware=[...]` **после** `session_config.middleware`
  (иначе в `scope["session"]` ещё ничего нет).
- Путь берётся из `raw_path` и **обрезается по `?`**: тестовый ASGI-транспорт кладёт туда
  query string, и без обрезки сравнение с `EXCLUDE_PATHS` ломается.
- Неавторизованный **fetch** (`Sec-Fetch-Mode` != `navigate`) получает `401` JSON, а не `303`:
  `fetch()` молча идёт по редиректу и отдаёт в JS HTML страницы логина, где `resp.json()` падает с
  `Unexpected token '<'`. Нет заголовка (curl, старый браузер) — считается навигацией → редирект.
- Сессия, протухшая по неактивности, очищается (`session.clear()`).

```python
import time

from litestar.types import ASGIApp, Receive, Scope, Send
from starlette.responses import JSONResponse, RedirectResponse


EXCLUDE_PATHS = {"/auth/login", "/auth/logout"}
EXCLUDE_PREFIXES = ("/static/",)
LOGIN_PATH = "/auth/login"

SESSION_TIMEOUT = 3600  # 1 hour in seconds


def _is_fetch(scope: Scope) -> bool:
    for name, value in scope.get("headers") or ():
        if name == b"sec-fetch-mode":
            return value.decode() != "navigate"
    return False


def _reject(scope: Scope, location: str, message: str) -> JSONResponse | RedirectResponse:
    if _is_fetch(scope):
        return JSONResponse(
            {"status": "error", "message": message, "relogin": True, "location": location},
            status_code=401,
        )
    return RedirectResponse(location, status_code=303)


class AuthMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        raw_path = scope.get("raw_path", b"")
        path = raw_path.decode() if isinstance(raw_path, bytes) else scope.get("path", "")
        path = path.split("?", 1)[0]
        session = scope.get("session", {})

        if any(path.startswith(p) for p in EXCLUDE_PREFIXES) or path in EXCLUDE_PATHS:
            await self.app(scope, receive, send)
            return

        if not session.get("user_id"):
            response = _reject(scope, LOGIN_PATH, "Вы не авторизованы — войдите заново")
            await response(scope, receive, send)
            return

        last_activity = session.get("last_activity")
        now = time.time()
        if last_activity and (now - last_activity) > SESSION_TIMEOUT:
            session.clear()
            response = _reject(scope, LOGIN_PATH, "Сессия истекла — войдите заново")
            await response(scope, receive, send)
            return

        session["last_activity"] = now
        await self.app(scope, receive, send)
```

## 5. Подключение в `app.py`

```python
from litestar import Litestar
from litestar.config.csrf import CSRFConfig
from litestar.middleware.session.client_side import CookieBackendConfig

from config import settings
from controllers.auth import AuthController
from middleware import AuthMiddleware

session_config = CookieBackendConfig(secret=settings.session_secret)

# No separate secret: session_secret is reused to HMAC-sign the CSRF token
# (a different cryptographic purpose than encrypting the session cookie).
csrf_config = CSRFConfig(secret=settings.session_secret.hex())

app = Litestar(
    route_handlers=[AuthController, ...],
    dependencies={"db_session": Provide(provide_db_session)},
    middleware=[session_config.middleware, AuthMiddleware],   # order matters
    csrf_config=csrf_config,
    ...
)
```

`session_config` экспортируется из `app.py` на уровне модуля — он нужен тестам (`TestClient(session_config=...)`).

Данные пользователя в шаблоны передаются явно из сессии в каждом контроллере:
```python
context={"user_id": request.session.get("user_id"), "fullname": request.session.get("fullname", ""), ...}
```

## 6. CSRF во фронтенде

`base.html` (в `<head>`):
```html
<meta name="csrf-token" content="{{ csrf_token() }}">
<script src="/static/js/api.js"></script>
```
и в навигации: `<a href="/auth/logout">Выйти</a>`, рядом `{{ fullname }}`.

Каждая обычная форма (включая `login.html`, которая **не** наследует `base.html`):
```html
<form method="post" action="/auth/login">
    <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
    <input type="text" name="username" required autofocus>
    <input type="password" name="password" required>
    <button type="submit">Войти</button>
</form>
{% if error %}<div class="alert alert-error">{{ error }}</div>{% endif %}
```

## 7. `static/js/api.js` — работа с 401 из JS

```javascript
function appendCsrfToken(formData) {
    formData.append('_csrf_token', document.querySelector('meta[name="csrf-token"]').content);
    return formData;
}

// AuthMiddleware answers any fetch with a 401, not only the ones expecting JSON:
// a file download cannot go through readJsonResponse, yet needs the same re-login.
async function throwIfUnauthorized(resp) {
    if (resp.status !== 401) return;

    let target = '/auth/login';
    try { target = (await resp.json()).location || target; } catch (e) {}
    window.location = target;
    throw new Error('Сессия завершена — выполняется переход на страницу входа');
}

async function readJsonResponse(resp) {
    await throwIfUnauthorized(resp);

    if (!(resp.headers.get('content-type') || '').includes('application/json')) {
        throw new Error('сервер ответил ' + resp.status + ' без JSON');
    }

    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || data.message || ('ошибка ' + resp.status));
    return data;
}

async function postForm(url, formData) {
    return readJsonResponse(await fetch(url, { method: 'POST', body: formData }));
}

async function getJson(url) {
    return readJsonResponse(await fetch(url));
}
```

Использование: `const data = await postForm('/x/run', appendCsrfToken(new FormData(form)));`
Все `fetch()` идут через `postForm`/`getJson`; скачивание файла — через `throwIfUnauthorized(resp)`.

## 8. Тесты (`tests/test_auth_middleware_json.py`)

```python
import time

import pytest
from litestar.testing import TestClient

from app import app, session_config


@pytest.fixture
def client():
    with TestClient(app=app, raise_server_exceptions=False, session_config=session_config) as c:
        yield c


FETCH_HEADERS = {"sec-fetch-mode": "cors"}


def test_expired_session_answers_fetch_with_json(client):
    client.set_session_data({"user_id": 1, "last_activity": time.time() - 99999})

    response = client.get("/some-protected-page/", headers=FETCH_HEADERS)

    assert response.status_code == 401
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["relogin"] is True


def test_navigation_redirects(client):
    response = client.get("/some-protected-page/", headers={"sec-fetch-mode": "navigate"}, follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/auth/login"
```



## Подводные камни Litestar (из опыта проекта)

- Обработчики в `exception_handlers` должны быть синхронными `def` — Litestar вызывает их без `await`.
- `Template(template_name=...)`, не `name=`.
- Форма логина — `Body(media_type=RequestEncodingType.URL_ENCODED)`, иначе Litestar ждёт JSON.
- Логин-форма тоже проходит CSRF-проверку: без скрытого `_csrf_token` будет `403`.
- Не выносить состояние в глобальные переменные сверх необходимого: всё, что относится к
  пользователю, — только в сессии.
