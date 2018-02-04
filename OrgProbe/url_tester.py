import contextlib
import hashlib
import logging

import requests

from .result import Result
from .signing import RequestSigner

logger = logging.getLogger(__name__)


DEFAULT_USER_AGENT = 'OrgProbe/2.0.0 (+http://www.blocked.org.uk)'


class UrlTester:

    def __init__(self, probe_config):
        self.signer = RequestSigner(probe_config['secret'])
        self.headers = {
            'User-Agent': probe_config.get('useragent', DEFAULT_USER_AGENT),
        }

        if 'verify_ssl' in probe_config:
            self.verify_ssl = (probe_config['verify_ssl'].lower() == 'true')
        else:
            self.verify_ssl = False

        self.timeout = int(probe_config.get('timeout', 5))

    def test_url(self, rules_matcher, url):
        logger.info("Testing URL: %s", url)
        try:
            with contextlib.closing(requests.get(
                    url,
                    headers=self.headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    stream=True
            )) as req:
                try:
                    ssl_verified = None
                    ssl_fingerprint = None
                    ip = self.get_peer_address(req)

                    logger.debug("Got IP: %s", ip)

                    if req.url.startswith('https'):
                        ssl_verified = req.raw.connection.is_verified
                        ssl_fingerprint = self.get_ssl_fingerprint(req)

                    result = rules_matcher.test_response(req)
                    result.ip = ip
                    result.ssl_fingerprint = ssl_fingerprint
                    result.ssl_verified = ssl_verified
                    result.final_url = req.url
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
        try:
            hexstr = hashlib.sha256(req.raw.connection.sock.getpeercert(True)).hexdigest()
            ssl_fingerprint = ":".join([hexstr[i:i + 2].upper() for i in range(0, len(hexstr), 2)])
            logger.info("Got fingerprint: %s", ssl_fingerprint)
            return ssl_fingerprint
        except Exception as exc:
            logger.debug("SSL fingerprint error: %s", exc)
            raise
