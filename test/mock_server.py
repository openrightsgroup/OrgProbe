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

    URL_MAP = {
        '/redir': 'send_redir',
        '/image.png': 'send_image',
        '/send-utf8': 'send_utf8',
        '/send-iso88591': 'send_iso88591',
        '/send-nocharset': 'send_nocharset_iso',
        '/send-nocharset-utf8': 'send_nocharset_utf8',
    }

    def do_GET(self):
        if self.path in self.URL_MAP:
            getattr(self, self.URL_MAP[self.path])()  # call named function
            return
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.send_header("Content-length", "87")
        self.end_headers()
        self.wfile.write("""<html>
<head>
<title>Title Text</title>
</head>
<body>
<h1>Hello!</h1>
</body>
</html>
""")

    def log_message(self, format, *args):
        pass

    def send_redir(self):
        self.send_response(302)
        self.send_header("Location", "/")
        self.send_header("Content-length", "16")
        self.end_headers()
        self.wfile.write("Redirecting to /")

    def send_image(self):
        try:
            self.send_response(200)
            self.send_header("Content-type", "image/png")
            self.send_header("Content-length", "16")
            self.end_headers()
            self.wfile.write("\x00" * 16)
        except IOError as exc:
            if exc.errno == 104:  # connection reset by peer
                # we expect the connection to hangup, since the probe
                # does not read image bodies
                pass
            raise

    def send_utf8(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=UTF-8')
        self.send_header('Content-length', '8')
        self.end_headers()
        self.wfile.write("\xc2\xa320 GBP")

    def send_iso88591(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=ISO-8859-1')
        self.send_header('Content-length', '7')
        self.end_headers()
        self.wfile.write("\xa320 GBP")

    def send_nocharset_iso(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-length', '7')
        self.end_headers()
        self.wfile.write("\xa320 GBP")

    def send_nocharset_utf8(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-length', '18')
        self.end_headers()
        self.wfile.write("\xc2\xa320 GBP, \xc2\xa390 GBP")

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
