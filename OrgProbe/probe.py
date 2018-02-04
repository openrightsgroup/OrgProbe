import json
import logging
import sys

from .middleware_api import MiddlewareAPI
from .signing import RequestSigner
from .url_tester import UrlTester
from .accounting import Accounting
from .amqpqueue import AMQPQueue
from .category import Categorizor
from .match import RulesMatcher

logger = logging.getLogger("probe")


class SelfTestError(Exception):
    pass


class Probe(object):

    def __init__(self, config):
        self.config = config

        # initialize configuration

        # set up in .run()
        self.probe = None
        self.signer = None
        self.url_tester = None
        self.middleware_api = None

        # set up in .configure()
        self.rules_matcher = None
        self.apiconfig = None
        self.isp = None
        self.ip = None
        self.counters = None
        self.queue = None

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
                api_config = json.load(fp)
                logger.info("Loaded config: %s from %s",
                            api_config['version'],
                            self.probe['api_config_file'])
        else:
            api_config = self.middleware_api.config(self.probe.get('config_version', 'latest'))
            logger.info("Loaded config: %s", api_config['version'])

        self.apiconfig = api_config

    def get_ip_status(self):
        data = self.middleware_api.status_ip(self.probe.get('public_ip'),
                                             self.probe['uuid'])
        logger.info("Network=%s", data)

        if 'network' in self.probe:
            self.isp = self.probe['network']
            logger.warn("Overriding network to: %s", self.isp)
        else:
            self.isp = data['isp']

        self.ip = data['ip']

        for rule in self.apiconfig['rules']:
            if rule['isp'] == self.isp:
                rules = rule['match']
                if 'category' in rule:
                    logger.debug("Creating Categorizor with rule: %s",
                                 rule['category'])
                    categorizor = Categorizor(rule['category'])
                else:
                    categorizor = None

                if 'blocktype' in rule:
                    logger.debug("Adding blocktype array: %s",
                                 rule['blocktype'])
                    blocktype = rule['blocktype']
                else:
                    blocktype = None

                self.rules_matcher = RulesMatcher(
                    rules,
                    blocktype,
                    categorizor,
                )
                break
        else:
            logger.error("No rules found for ISP: %s", self.isp)
            if self.probe.get('skip_rules', 'false').lower() == 'true':
                rules = []
                self.rules_matcher = RulesMatcher(
                    rules,
                    [],
                    None
                )
            else:
                sys.exit(1)

        logger.debug("Got rules: %s", rules)

    def setup_accounting(self):
        if not self.config.get('accounting', 'redis_server', fallback=None):
            self.counters = None
            return
        self.counters = Accounting(self.config,
                                   self.isp.lower().replace(' ', '_'), self.probe)
        self.counters.check()

    def setup_queue(self):
        opts = dict(self.config.items('amqp'))
        logger.debug("Setting up AMQP with options: %s", opts)
        lifetime = int(self.probe['lifetime']) if 'lifetime' in \
                                                  self.probe else None
        self.queue = AMQPQueue(opts,
                               self.isp.lower().replace(' ', '_'),
                               self.probe.get('queue', 'org'),
                               self.signer,
                               self.run_test,
                               lifetime,
                               )

    def test_and_report_url(self, url, urlhash=None, request_id=None):
        result = self.url_tester.test_url(self.rules_matcher, url)

        # logger.info("Result: %s; %s", request_id, result)

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
            'ssl_fingerprint': result.ssl_fingerprint,
            'request_id': request_id,
            'final_url': result.final_url
        }
        if self.probe.get('verify_ssl', '').lower() == 'true':
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
            if self.url_tester.test_url(self.rules_matcher, url).status != 'ok':
                raise SelfTestError
        for url in self.apiconfig['self-test']['must-block']:
            if self.url_tester.test_url(self.rules_matcher, url).status != 'blocked':
                raise SelfTestError

    def run_test(self, data):
        if self.counters:
            self.counters.requests.add(1)

        if 'url' in data:
            self.test_and_report_url(data['url'], data['hash'], data.get('request_id'))
        elif 'urls' in data:
            for url in data['urls']:
                self.test_and_report_url(url['url'], data['hash'], request_id=data.get('request_id'))

    def run(self, probe_name=None):
        if not probe_name:
            try:
                probe_name = [x for x in self.config.sections() if
                              x not in ('amqp', 'api', 'global')][0]
            except IndexError:
                logger.error("No probe identity configuration found")
                return 1

        logger.info("Using probe: %s", probe_name)

        self.probe = dict([(x, self.config.get(probe_name, x))
                           for x in self.config.options(probe_name)
                           ])
        self.url_tester = UrlTester(self.probe)
        self.signer = RequestSigner(self.probe['secret'])
        self.middleware_api = MiddlewareAPI(self.config, self.signer)
        self.configure()
        self.queue.start()
