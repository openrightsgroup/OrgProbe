import BaseHTTPServer
import SocketServer
import os
import ssl
from contextlib import contextmanager
import thread


CERTIFICATE_FINGERPRINT = \
    "42:6D:9E:65:5A:25:2A:DA:23:EE:FC:60:22:5C:51:91:6E:C1:8E:45:7C:C5:05:12:56:C5:D3:CD:7E:74:A0:B9"


class HttpHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    # Probe requires connections to be kept alive (eg. usage of connection.sock),
    # this is easiest to do via HTTP/1.1.
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        # Don't care about the request path.
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.send_header("Content-length", "2")
        self.end_headers()
        self.wfile.write('OK')

    def log_message(self, format, *args):
        pass


@contextmanager
def https_server_that_returns_success():
    keyfile = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                           'ssl_certs',
                           'localhost.key')
    certfile = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                            'ssl_certs',
                            'localhost.crt')

    server = BaseHTTPServer.HTTPServer(("localhost", 0), HttpHandler)
    server.socket = ssl.wrap_socket(server.socket,
                                    keyfile=keyfile,
                                    certfile=certfile,
                                    server_side=True)
    try:
        thread.start_new_thread(server.handle_request, ())
        yield server.server_address[1]
    finally:
        server.server_close()


@contextmanager
def http_server_that_returns_success():
    server = BaseHTTPServer.HTTPServer(("localhost", 0), HttpHandler)
    try:
        thread.start_new_thread(server.handle_request, ())
        yield server.server_address[1]
    finally:
        server.server_close()


@contextmanager
def tcp_server_that_times_out():

    class EmptyHandler(SocketServer.BaseRequestHandler):
        def handle(self):
            pass

    server = SocketServer.TCPServer(("localhost", 0), EmptyHandler)
    try:
        yield server.server_address[1]
        # Don't handle any requests!
    finally:
        server.server_close()
