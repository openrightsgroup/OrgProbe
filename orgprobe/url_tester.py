import contextlib
import hashlib
import logging
import re


import requests

from .result import Result
from .signing import RequestSigner

logger = logging.getLogger(__name__)


DEFAULT_USER_AGENT = 'OrgProbe/2.2.0 (+http://www.blocked.org.uk)'


class UrlTester:
    READ_SIZE = 8192

    def __init__(self, probe_config, counters, rules_matcher):
        self.counters = counters
        self.rules_matcher = rules_matcher
        self.signer = RequestSigner(probe_config['secret'])
        self.headers = {
            'User-Agent': probe_config.get('useragent', DEFAULT_USER_AGENT),
        }

        if 'verify_ssl' in probe_config:
            self.verify_ssl = (probe_config['verify_ssl'].lower() == 'true')
        else:
            self.verify_ssl = False

        self.do_record_request_data = (probe_config.get('record_requests','').lower() == 'true')

        self.timeout = int(probe_config.get('timeout', 5))

    def test_url(self, url):
        logger.info("Testing URL: %s", url)

        if self.counters:
            self.counters.requests.add(1)

        result = self._test_url_no_accounting(url)

        if self.counters and result.body_length is not None:
            self.counters.check()
            self.counters.bytes.add(result.body_length)
        
        logger.info("Result for: %s : %s", url, result.status)
        return result

    def _make_request(self, url):
        return requests.get(
            url,
            headers=self.headers,
            timeout=self.timeout,
            verify=self.verify_ssl,
            stream=True,
            hooks={'response': self.run_response_hooks}
        )

    def _test_url_no_accounting(self, url):
        try:
            with contextlib.closing(self._make_request(url)) as req:
                try:
                    ip = req.peername

                    body = self.fetch_body(req)

                    result = self.rules_matcher.test_response(req, body)
                    result.ip = req.peername
                    logger.debug("Got IP: %s", result.ip)
                    result.resolved_ip = req.history[0].peername if req.history else req.peername
                    result.ssl_fingerprint = req.ssl_fingerprint
                    result.ssl_verified = req.ssl_verified
                    result.final_url = req.url
                    result._title = self.extract_title(body)
                    result.request_data = self.record_request_data(req, body)
                    return result
                except Exception as v:
                    logger.error("Response test error: %s", v)
                    raise
        except requests.exceptions.SSLError as v:
            logger.warn("SSL Error: %s", v)
            return Result('sslerror', -1)

        except requests.exceptions.Timeout as v:
            logger.warn("Connection timeout: %s", v)
            return Result('timeout', -1, final_url=v.request.url)

        except requests.exceptions.ConnectionError as v:
            logger.warn("Connection error: %s", v)

            try:
                # look for dns failure in exception message
                # requests lib turns nested exceptions into strings
                if 'Name or service not known' in v.args[0].message:
                    logger.info("DNS resolution failed(1)")
                    return Result('dnserror', -1, final_url=v.request.url)
            except:
                pass
            try:
                # look for dns failure in exception message
                if 'Name or service not known' in v.args[0][1].strerror:
                    logger.info("DNS resolution failed(2)")
                    return Result('dnserror', -1, final_url=v.request.url)
            except:
                pass
            return Result('timeout', -1, final_url=v.request.url)

        except Exception as v:
            logger.warn("Connection error: %s", v)
            return Result('error', -1)

    def get_body_iter(self, req):
        return req.iter_content(self.READ_SIZE)

    def fetch_body(self, req):
        if req.headers['content-type'].lower().startswith('text'):
            body = next(self.get_body_iter(req))
        else:
            # we're not downloading images
            body = ''
        return body

    def record_request_data(self, req, body):

        if not self.do_record_request_data:
            return None

        def hashmethod(x):
            return hashlib.sha256(x).hexdigest()

        out = []
        for r in req.history + [req]:
            content = None
            hashcalc = hashlib.sha256()

            if r is req:  # last step in the history
                content = body
                hashcalc.update(body)
                contentiter = self.get_body_iter(req)
            else:
                contentiter = self.get_body_iter(r)

            for part in contentiter:
                if content is None:
                    content = part  # save first part for history recording
                hashcalc.update(part)

            rq = r.request
            out.append({
                'req': {
                    'url': rq.url,
                    'headers': dict(rq.headers.items()),
                    'body': rq.body or None,
                    'hash': hashmethod(rq.body) if rq.body else None,
                    'method': rq.method
                    },
                'rsp': {
                    'headers': dict(r.headers.items()),
                    'content': content[:1024] if content else None,
                    'hash': hashcalc.hexdigest() if content else None,
                    'status': r.status_code,
                    'ssl_fingerprint': r.ssl_fingerprint,
                    'ssl_verified': r.ssl_verified,
                    'ip': r.peername,
                    }
                })
        return out

    @classmethod
    def run_response_hooks(cls, r, *args, **kw):
        r.peername = cls.get_peer_address(r)
        r.ssl_fingerprint = cls.get_ssl_fingerprint(r)
        r.ssl_verified = cls.get_ssl_is_verified(r)

    @staticmethod
    def get_peer_address(req):
        try:
            # Non-SSL
            return req.raw.connection.sock.getpeername()[0]
        except Exception as exc:
            logger.debug("IP trace error: %s", exc)
        try:
            # SSL version
            return req.raw.connection.sock.socket.getpeername()[0]
        except Exception as exc:
            logger.debug("IP trace error: %s", exc)

    @staticmethod
    def get_ssl_fingerprint(req):
        if not req.url.startswith('https:'):
            return None
        try:
            hexstr = hashlib.sha256(req.raw.connection.sock.getpeercert(True)).hexdigest()
            ssl_fingerprint = ":".join([hexstr[i:i + 2].upper() for i in range(0, len(hexstr), 2)])
            logger.info("Got fingerprint: %s", ssl_fingerprint)
            return ssl_fingerprint
        except Exception as exc:
            logger.debug("SSL fingerprint error: %s", exc)
            raise

    @staticmethod
    def get_ssl_is_verified(req):
        if not req.url.startswith('https:'):
            return None
        return req.raw.connection.is_verified

    @staticmethod
    def extract_title(content):
        match = re.search(b'<title>(.*?)</title', content, re.S + re.I + re.M)
        if match:
            return match.group(1).decode('utf8', 'replace').strip()
