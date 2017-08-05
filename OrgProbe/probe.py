import re
import sys
import json
import time
import logging
import requests
import hashlib
import contextlib

from .api import RegisterProbeRequest, PrepareProbeRequest, StatusIPRequest, \
    ConfigRequest
from .signing import RequestSigner
from .category import Categorizor
from .accounting import Accounting,OverLimitException
from .match import RulesMatcher
from .amqpqueue import AMQPQueue

class SelfTestError(Exception):
    pass


class Probe(object):
    DEFAULT_USERAGENT = 'OrgProbe/0.9.4 (+http://www.blocked.org.uk)'

    def __init__(self, config):
        self.config = config

        # initialize configuration

        # set up in .run()
        self.probe = None
        self.signer = None
        self.headers = {}
        self.read_size = 8192  # size of body to read
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
        logging.info("Status: %s, %s", code, data)
        if 'network' in self.probe:
            self.isp = self.probe['network']
            logging.debug("Overriding network to: %s", self.isp)
        else:
            self.isp = data['isp']

        self.ip = data['ip']

        for rule in self.apiconfig['rules']:
            if rule['isp'] == self.isp:
                self.rules = rule['match']
                if 'category' in rule:
                    logging.info("Creating Categorizor with rule: %s",
                                 rule['category'])
                    categorizor = Categorizor(rule['category'])
                else:
                    categorizor = None

                if 'blocktype' in rule:
                    logging.info("Adding blocktype array: %s",
                                 rule['blocktype'])
                    blocktype = rule['blocktype']
                else:
                    blocktype = None

                self.rules_matcher = RulesMatcher(
                    self.rules,
                    blocktype,
                    categorizor,
                    self.read_size
                    )
                break
        else:
            logging.error("No rules found for ISP: %s", self.isp)
            if self.probe.get('skip_rules', 'false').lower() == 'true':
                self.rules = []
            else:
                sys.exit(1)

        logging.info("Got rules: %s", self.rules)

    def setup_accounting(self):
        if not self.config.has_section('accounting'):
            self.counters = None
            return
        self.counters = Accounting(self.config, 
            self.isp.lower().replace(' ','_'), self.probe)
        self.counters.check()

    def setup_queue(self):
        opts = dict(self.config.items('amqp'))
        logging.info("Setting up AMQP with options: %s", opts)
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
                    return self.rules_matcher.test_response(req)
                except Exception as v:
                    logging.error("Response test error: %s", v)
                    raise
        except requests.exceptions.SSLError as v:
            logging.warn("SSL Error: %s", v)
            return 'sslerror', -1, None, None
        except requests.exceptions.Timeout as v:
            logging.warn("Connection timeout: %s", v)
            return 'timeout', -1, None, None
        except Exception as v:
            logging.warn("Connection error: %s", v)
            try:
                # look for dns failure in exception message
                # requests lib turns nested exceptions into strings
                if 'Name or service not known' in v.args[0].message:
                    logging.info("DNS resolution failed(1)")
                    return 'dnserror', -1, None, None
            except:
                pass
            try:
                # look for dns failure in exception message
                if 'Name or service not known' in v.args[0][1].strerror:
                    logging.info("DNS resolution failed(2)")
                    return 'dnserror', -1, None, None
            except:
                pass
            raise
            return 'error', -1, None, None

    def test_and_report_url(self, url, urlhash=None):
        result, code, category, blocktype = self.test_url(url)

        logging.info("Logging result with ORG: %s, %s", result, code)

        report = {
            'network_name': self.isp,
            'ip_network': self.ip,
            'url': url,
            'http_status': code,
            'status': result,
            'probe_uuid': self.probe['uuid'],
            'config': self.apiconfig['version'],
            'category': category or '',
            'blocktype': blocktype or '',
        }

        self.queue.send(report, urlhash)
        if self.counters:
            self.counters.check()


    def run_selftest(self):
        if self.probe.get('selftest', 'true').lower() != 'true':
            return

        for url in self.apiconfig['self-test']['must-allow']:
            if self.test_url(url)[0] != 'ok':
                raise SelfTestError
        for url in self.apiconfig['self-test']['must-block']:
            if self.test_url(url)[0] != 'blocked':
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

        if 'read_size' in self.probe:
            self.read_size = int(self.probe['read_size'])

        if 'verify_ssl' in self.probe:
            self.verify_ssl = (self.probe['verify_ssl'].lower() == 'true')

        self.configure()
        self.queue.start()

        #try:
        #    logging.info("Exiting cleanly")
        #except OverLimitException:
        #    logging.info("Exiting due to byte limit")
