import re
import sys
import json
import time
import logging
import requests
import hashlib
import socket
import contextlib

from .api import RegisterProbeRequest, PrepareProbeRequest, StatusIPRequest, \
    ConfigRequest
from .signing import RequestSigner
from .category import Categorizor
from .accounting import Accounting,OverLimitException
from .match import RulesMatcher
from .amqpqueue import AMQPQueue
from .result import Result

class SelfTestError(Exception):
    pass


class Probe(object):
    DEFAULT_USERAGENT = 'OrgProbe/2.0.0 (+http://www.blocked.org.uk)'

    def __init__(self, config):
        self.config = config

        # initialize configuration

        # set up in .run()
        self.probe = None
        self.signer = None
        self.headers = {}
        self.verify_ssl = False

        # set up in .configure()

        self.apiconfig = None
        self.isp = None
        self.ip = None

        pass


    def configure(self):
        self.get_api_config()
        self.get_ip_status()
        self.setup_accounting()
        self.run_selftest()
        self.setup_queue()

    def get_api_config(self):
        if self.probe.get('api_config_file'):
            with open(self.probe['api_config_file']) as fp:
                self.apiconfig = json.load(fp)
                logging.info("Loaded config: %s from %s",
                             self.apiconfig['version'],
                             self.probe['api_config_file'])

            return
        req = ConfigRequest(None, self.probe.get('config_version', 'latest'))
        code, data = req.execute()
        if code == 200:
            logging.info("Loaded config: %s", data['version'])
            self.apiconfig = data
            logging.debug("Got config: %s", data)
        elif code == 304:
            pass
        else:
            logging.error("Error downloading config: %s, %s", code,
                          data['error'])

    def get_ip_status(self):
        try:
            args = (self.probe['public_ip'],)
        except KeyError:
            args = []
        req = StatusIPRequest(self.signer, *args,
                              probe_uuid=self.probe['uuid'])
        code, data = req.execute()
        logging.info("Status: %s; Network=%s", code, data)
        if 'network' in self.probe:
            self.isp = self.probe['network']
            logging.warn("Overriding network to: %s", self.isp)
        else:
            self.isp = data['isp']

        self.ip = data['ip']

        for rule in self.apiconfig['rules']:
            if rule['isp'] == self.isp:
                self.rules = rule['match']
                if 'category' in rule:
                    logging.debug("Creating Categorizor with rule: %s",
                                 rule['category'])
                    categorizor = Categorizor(rule['category'])
                else:
                    categorizor = None

                if 'blocktype' in rule:
                    logging.debug("Adding blocktype array: %s",
                                 rule['blocktype'])
                    blocktype = rule['blocktype']
                else:
                    blocktype = None

                self.rules_matcher = RulesMatcher(
                    self.rules,
                    blocktype,
                    categorizor,
                    )
                break
        else:
            logging.error("No rules found for ISP: %s", self.isp)
            if self.probe.get('skip_rules', 'false').lower() == 'true':
                self.rules = []
            else:
                sys.exit(1)

        logging.debug("Got rules: %s", self.rules)

    def setup_accounting(self):
        if not self.config.has_section('accounting'):
            self.counters = None
            return
        self.counters = Accounting(self.config, 
            self.isp.lower().replace(' ','_'), self.probe)
        self.counters.check()

    def setup_queue(self):
        opts = dict(self.config.items('amqp'))
        logging.debug("Setting up AMQP with options: %s", opts)
        lifetime = int(self.probe['lifetime']) if 'lifetime' in \
                                                  self.probe else None
        self.queue = AMQPQueue(opts,
                               self.isp.lower().replace(' ', '_'),
                               self.probe.get('queue', 'org'),
                               self.signer,
                               self.run_test,
                               lifetime, 
                               )


    def test_url(self, url):
        logging.info("Testing URL: %s", url)
        try:
            with contextlib.closing(requests.get(
                    url,
                    headers=self.headers,
                    timeout=int(self.probe.get('timeout', 5)),
                    verify=self.verify_ssl,
                    stream=True
            )) as req:
                try:
                    ssl_fingerprint = None
                    ip = self.get_peer_address(req)
                    ssl_verified = req.raw.connection.is_verified

                    logging.debug("Got IP: %s", ip)
                        
                    if url.startswith('https'):
                        try:
                            ssl_fingerprint = req.raw.connection.sock.connection.get_peer_certificate().digest('sha256')
                            logging.debug("Got fingerprint: 5s", ssl_fingerprint)
                        except Exception as exc:
                            logging.debug("SSL fingerprint error: %s", exc)

                    result = self.rules_matcher.test_response(req)
                    result.ip = ip
                    result.ssl_fingerprint = ssl_fingerprint
                    result.ssl_verified = ssl_verified
                    return result
                except Exception as v:
                    logging.error("Response test error: %s", v)
                    raise
        except requests.exceptions.SSLError as v:
            logging.warn("SSL Error: %s", v)
            return Result('sslerror', -1)

        except requests.exceptions.Timeout as v:
            logging.warn("Connection timeout: %s", v)
            return Result('timeout', -1)
        
        except Exception as v:
            logging.warn("Connection error: %s", v)
            try:
                # look for dns failure in exception message
                # requests lib turns nested exceptions into strings
                if 'Name or service not known' in v.args[0].message:
                    logging.info("DNS resolution failed(1)")
                    return Result('dnserror', -1)
            except:
                pass
            try:
                # look for dns failure in exception message
                if 'Name or service not known' in v.args[0][1].strerror:
                    logging.info("DNS resolution failed(2)")
                    return Result('dnserror', -1)
            except:
                pass
            return Result('error', -1)

    def get_peer_address(self, req):
        try:
            # Non-SSL
            return req.raw.connection.sock.getpeername()[0]
        except Exception as exc:
            logging.debug("IP trace error: %s", exc)
        try:
            # SSL version
            return req.raw.connection.sock.socket.getpeername()[0]
        except Exception as exc:
            logging.debug("IP trace error: %s", exc)


    def test_and_report_url(self, url, urlhash=None):
        result = self.test_url(url)

        logging.info("Logging result: %s", result)

        report = {
            'network_name': self.isp,
            'ip_network': self.ip,
            'url': url,
            'http_status': result.code,
            'status': result.status,
            'probe_uuid': self.probe['uuid'],
            'config': self.apiconfig['version'],
            'category': result.category or '',
            'blocktype': result.type or '',
            'title': result.title or '',
            'remote_ip': result.ip or '',
            'ssl_verified': None,
            'ssl_fingerprint': result.ssl_fingerprint
        }
        if self.probe.get('verify_ssl','').lower() == 'true':
            report.update({
                'ssl_verified': result.ssl_verified,
                })

        self.queue.send(report, urlhash)
        if self.counters:
            self.counters.check()
            self.counters.bytes.add(result.body_length)


    def run_selftest(self):
        if self.probe.get('selftest', 'true').lower() != 'true':
            return

        for url in self.apiconfig['self-test']['must-allow']:
            if self.test_url(url).status != 'ok':
                raise SelfTestError
        for url in self.apiconfig['self-test']['must-block']:
            if self.test_url(url).status != 'blocked':
                raise SelfTestError

    def run_test(self, data):
        if self.counters:
            self.counters.requests.add(1)


        if 'url' in data:
            self.test_and_report_url(data['url'], data['hash'])
        elif 'urls' in data:
            for url in data['urls']:
                self.test_and_report_url(url['url'], data['hash'])


    def run(self, args):
        if args.profile:
            self.probename = args.profile
        else:
            try:
                self.probename = [x for x in self.config.sections() if
                                  x not in ('amqp', 'api', 'global')][0]
            except IndexError:
                logging.error("No probe identity configuration found")
                return 1

        logging.info("Using probe: %s", self.probename)

        self.probe = dict([(x, self.config.get(self.probename, x))
                           for x in self.config.options(self.probename)
                           ])

        self.signer = RequestSigner(self.probe['secret'])
        self.headers = {
            'User-Agent': self.probe.get('useragent', self.DEFAULT_USERAGENT),
        }

        if 'verify_ssl' in self.probe:
            self.verify_ssl = (self.probe['verify_ssl'].lower() == 'true')

        self.configure()
        self.queue.start()

        #try:
        #    logging.info("Exiting cleanly")
        #except OverLimitException:
        #    logging.info("Exiting due to byte limit")
