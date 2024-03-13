import contextlib
import hashlib
import logging
import re


import requests
import chardet

from .result import Result
from .signing import RequestSigner

logger = logging.getLogger(__name__)


DEFAULT_USER_AGENT = 'OrgProbe/2.2.0 (+http://www.blocked.org.uk)'
NAME_NOT_FOUND = 'Name or service not known'

class UrlTester:
    READ_SIZE = 8192

    def __init__(self, probe_config, rules_matcher):
        self.rules_matcher = rules_matcher
        self.signer = RequestSigner(probe_config['secret'])
        self.headers = {
            'User-Agent': probe_config.get('useragent', DEFAULT_USER_AGENT),
        }

        if 'verify_ssl' in probe_config:
            self.verify_ssl = (probe_config['verify_ssl'].lower() == 'true')
        else:
            self.verify_ssl = False

        self.do_record_request_data = (probe_config.get('record_requests', '').lower() == 'true')

        self.timeout = int(probe_config.get('timeout', 5))

    def test_url(self, url):
        logger.info("Testing URL: %s", url)


        result = self._test_url_no_accounting(url)


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
                    body = self.fetch_body(req)

                    result = self.rules_matcher.test_response(req, body)
                    result.ip = req.peername
                    logger.debug("Got IP: %s", result.ip)
                    result.resolved_ip = req.history[0].peername if req.history else req.peername
                    result.ssl_fingerprint = req.ssl_fingerprint
                    result.ssl_verified = req.ssl_verified
                    result.final_url = req.url
                    result._title = self.extract_title(body)
                    result.request_data = self.record_request_data(req)

                    if self.do_record_request_data:
                        hashcalc = hashlib.sha256()

                        if body is not None:
                            hashcalc.update(body)

                        req_record = self.create_request_record(req)

                        req_record['rsp'].update({
                            'content': body or None,
                            'hash': hashcalc.hexdigest() if body else None,
                        })

                        result.request_data.append(req_record)

                    return result
                except Exception as v:
                    logger.error("Response test error: %s: %s", repr(v), v)
                    raise
        except requests.exceptions.SSLError as v:
            logger.warning("SSL Error: %s", v)
            return Result('sslerror', -1)

        except requests.exceptions.Timeout as v:
            logger.warning("Connection timeout: %s", v)
            return Result('timeout', -1, final_url=v.request.url)

        except requests.exceptions.ConnectionError as v:
            logger.warning("Connection error: %s", v)

            try:
                # look for dns failure in exception message
                # requests lib turns nested exceptions into strings
                if NAME_NOT_FOUND in v.args[0].message:
                    logger.info("DNS resolution failed(1)")
                    return Result('dnserror', -1, final_url=v.request.url)
            except:
                pass

            try:
                # look for dns failure in exception message
                if NAME_NOT_FOUND in v.args[0][1].strerror:
                    logger.info("DNS resolution failed(2)")
                    return Result('dnserror', -1, final_url=v.request.url)
            except:
                pass

            try:
                # look for dns failure in exception message
                if NAME_NOT_FOUND in v.args[0].args[0]:
                    logger.info("DNS resolution failed(3)")
                    return Result('dnserror', -1, final_url=v.request.url)
            except:
                pass

            return Result('timeout', -1, final_url=v.request.url)

        except Exception as v:
            logger.warning("Connection error: %s", v)
            return Result('error', -1)

    def fetch_body(self, req):
        if req.headers.get('content-type', '').lower().startswith('text'):
            return req.text
        else:
            # we're not downloading images
            body = None
        return body

    @staticmethod
    def hash(s):
        return hashlib.sha256(s).hexdigest()

    def record_request_data(self, req):
        if not self.do_record_request_data:
            return None

        out = []
        for r in req.history:
            request_record = self.create_request_record(r)
            request_record['rsp'].update({
                'content': r.text or None,
                'hash': self.hash(r.content) if r.content else None,
            })
            out.append(request_record)
        return out

    def create_request_record(self, r):
        rq = r.request
        return {
            'req': {
                'url': rq.url,
                'headers': rq.headers.items(),
                'body': rq.body or None,
                'hash': self.hash(rq.body) if rq.body else None,
                'method': rq.method
            },
            'rsp': {
                'headers': r.headers.items(),
                'status': r.status_code,
                'ssl_fingerprint': r.ssl_fingerprint,
                'ssl_verified': r.ssl_verified,
                'ip': r.peername,
            }
        }

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
            logger.warn("SSL fingerprint error: %s", exc)

    @staticmethod
    def get_ssl_is_verified(req):
        if not req.url.startswith('https:'):
            return None
        return req.raw.connection.is_verified

    @staticmethod
    def extract_title(content):
        if isinstance(content, str):
            if match := re.search('<title>(.*?)</title', content, re.S + re.I + re.M):
                return match.group(1).strip()
        else:
            if match := re.search(b'<title>(.*?)</title', content, re.S + re.I + re.M):
                return match.group(1).decode('utf8', 'replace').strip()

