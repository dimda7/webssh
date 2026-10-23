import logging
import sys
import tornado.web
import tornado.ioloop

from tornado.options import options
from webssh import handler
from webssh.handler import (
    IndexHandler, WsockHandler, NotFoundHandler, SignInHandler,
    SignOutHandler, SIGNIN_URL, SIGNOUT_URL, ADMIN_USERS_URL, ACCOUNT_URL
)
from webssh.admin import AccountHandler, UserHandler, UsersHandler
from webssh.signin import ConfigError
from webssh.settings import (
    get_app_settings,  get_host_keys_settings, get_policy_setting,
    get_ssl_context, get_server_settings, check_encoding_setting
)


def make_handlers(loop, options):
    host_keys_settings = get_host_keys_settings(options)
    policy = get_policy_setting(options, host_keys_settings)

    handlers = [
        (r'/', IndexHandler, dict(loop=loop, policy=policy,
                                  host_keys_settings=host_keys_settings)),
        (r'/ws', WsockHandler, dict(loop=loop))
    ]
    if options.authdb:
        handlers += [
            (SIGNIN_URL, SignInHandler),
            (SIGNOUT_URL, SignOutHandler),
            (ADMIN_USERS_URL, UsersHandler),
            (ADMIN_USERS_URL + r'/(\d+)', UserHandler),
            (ACCOUNT_URL, AccountHandler)
        ]
    return handlers


def make_app(handlers, settings):
    settings.update(default_handler_class=NotFoundHandler)
    return tornado.web.Application(handlers, **settings)


def app_listen(app, port, address, server_settings):
    app.listen(port, address, **server_settings)
    if not server_settings.get('ssl_options'):
        server_type = 'http'
    else:
        server_type = 'https'
        handler.redirecting = True if options.redirect else False
    logging.info(
        'Listening on {}:{} ({})'.format(address, port, server_type)
    )


def main():
    options.parse_command_line()
    check_encoding_setting(options.encoding)
    loop = tornado.ioloop.IOLoop.current()
    try:
        app = make_app(make_handlers(loop, options),
                       get_app_settings(options))
    except ConfigError as exc:
        # a misconfiguration, not a bug: no traceback for the operator
        logging.error(exc)
        sys.exit(1)
    ssl_ctx = get_ssl_context(options)
    server_settings = get_server_settings(options)
    app_listen(app, options.port, options.address, server_settings)
    if ssl_ctx:
        server_settings.update(ssl_options=ssl_ctx)
        app_listen(app, options.sslport, options.ssladdress, server_settings)
    loop.start()


if __name__ == '__main__':
    main()
