import json
import logging
import sys

from .probe import (Probe, SelfTestError)
from .middleware_api import MiddlewareAPI
from .signing import RequestSigner
from .url_tester import UrlTester
from .amqpqueue import AMQPQueue
from .category import Categorizor
from .match import RulesMatcher

logger = logging.getLogger("bootstrapper")


def run(config, probe_name=None, selftest=False):

    probe_config = _extract_probe_config(
        config=config,
        probe_name=probe_name
    )
    logger.info("Running with probe config: %s", probe_config)

    signer = RequestSigner(
        secret=probe_config['secret']
    )
    middleware_api = MiddlewareAPI(
        config=config,
        signer=signer
    )
    apiconfig = _get_api_config(
        probe_config=probe_config,
        middleware_api=middleware_api
    )
    (isp, ip) = _get_ip_status(
        middleware_api=middleware_api,
        probe_config=probe_config
    )
    rules_matcher = _get_rules_matcher(
        apiconfig=apiconfig,
        probe_config=probe_config,
        isp=isp
    )
    url_tester = UrlTester(
        probe_config=probe_config,
        rules_matcher=rules_matcher
    )
    queue = _setup_queue(
        config=config,
        probe_config=probe_config,
        signer=signer,
        isp=isp,
    )
    probe = Probe(url_tester=url_tester,
                  queue=queue,
                  isp=isp,
                  ip=ip,
                  probe_config=probe_config,
                  apiconfig=apiconfig)

    logger.info("Bootstrap complete")

    try:
        probe.run_startup_selftest(selftest)
        if selftest:
            print(f"OK - {isp} self-test pass")
            return 0
    except SelfTestError as exc:
        if selftest:
            print(f"CRITICAL - {isp} self-test fail")
            return 3
        raise


    logger.info("Entering run mode")
    queue.start(callback=probe.run_test)


def _extract_probe_config(config, probe_name):
    if not probe_name:
        try:
            probe_name = [x for x in config.sections() if
                          x not in ('amqp', 'api', 'global')][0]
        except IndexError:
            logger.error("No probe identity configuration found")
            return 1

    logger.info("Using probe: %s", probe_name)

    return dict((x, config.get(probe_name, x)) for x in config.options(probe_name))


def _get_api_config(probe_config, middleware_api):
    if probe_config.get('api_config_file'):
        with open(probe_config['api_config_file']) as fp:
            api_config = json.load(fp)
            logger.info("Loaded config: %s from %s",
                        api_config['version'],
                        probe_config['api_config_file'])
    else:
        api_config = middleware_api.config(probe_config.get('config_version', 'latest'))
        logger.info("Loaded config: %s", api_config['version'])

    return api_config


def _get_ip_status(middleware_api, probe_config):
    data = middleware_api.status_ip(probe_config.get('public_ip'),
                                    probe_config['uuid'])
    logger.info("Network=%s", data)

    if 'network' in probe_config:
        isp = probe_config['network']
        logger.warn("Overriding network to: %s", isp)
    else:
        isp = data['isp']

    ip = data['ip']

    return (isp, ip)


def _get_rules_matcher(apiconfig, probe_config, isp):
    for rule in apiconfig['rules']:
        if rule['isp'] == isp:
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

            return RulesMatcher(
                rules,
                blocktype,
                categorizor,
            )

    logger.error("No rules found for ISP: %s", isp)
    if probe_config.get('skip_rules', 'false').lower() == 'true':
        rules = []
        return RulesMatcher(
            rules,
            [],
            None
        )
    else:
        logger.error("No rules found and skip_rules=false, terminating")
        sys.exit(1)



def _setup_queue(config, probe_config, signer, isp):
    opts = dict(config.items('amqp'))
    logger.debug("Setting up AMQP with options: %s", opts)
    lifetime = int(probe_config['lifetime']) if 'lifetime' in probe_config else None
    return AMQPQueue(opts,
                     isp.lower().replace(' ', '_'),  # TODO: get queue name from API response
                     probe_config.get('queue', 'org'),
                     signer,
                     lifetime)
