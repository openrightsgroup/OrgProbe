import json
from collections import namedtuple

import pytest
from configparser import ConfigParser
from mock import Mock
from pytest import raises

from OrgProbe import probe as ProbeModule
from OrgProbe.amqpqueue import AMQPQueue
from OrgProbe.middleware_api import MiddlewareAPI
from OrgProbe.probe import Probe, SelfTestError
from OrgProbe.result import Result
from OrgProbe.url_tester import UrlTester


@pytest.fixture
def mock_probe_config():
    config = ConfigParser()

    config.add_section('global')
    config.set('global', 'interval', '1')

    config.add_section('api')
    config.set('api', 'host', 'api.blocked.org.uk')
    config.set('api', 'port', '443')
    config.set('api', 'https', 'True')
    config.set('api', 'version', '1.2')

    config.add_section('amqp')
    config.set('amqp', 'host', 'localhost')
    config.set('amqp', 'port', '5672')
    config.set('amqp', 'ssl', 'False')
    config.set('amqp', 'userid', 'guest')
    config.set('amqp', 'passwd', 'guest')
    config.set('amqp', 'prefetch', '200')

    config.add_section('probe')
    config.set('probe', 'uuid', '01234567890123456788')
    config.set('probe', 'secret', 'secret')
    config.set('probe', 'queue', 'org')
    config.set('probe', 'selftest', 'False')

    return config


@pytest.fixture
def mock_amqp_queue(monkeypatch):
    class MockAMQPQueueWrapper(object):
        def __init__(self):
            self.queue = Mock(AMQPQueue)
            self.callback = None

        def constructor(self,
                        opts,
                        network,
                        queue_name,
                        signer,
                        callback,
                        *args):
            self.callback = callback
            return self.queue

    mock_amqp_queue_wrapper = MockAMQPQueueWrapper()
    monkeypatch.setattr(ProbeModule, 'AMQPQueue', mock_amqp_queue_wrapper.constructor)
    return mock_amqp_queue_wrapper


@pytest.fixture
def mock_middleware_api(monkeypatch):
    config = """
    {
        "org-block-rules": "0.2.3",
        "rules": [
            {
                "isp": "T-Mobile",
                "match": [
                    "re:body:TMobileBodyRule"
                ]
            },
            {
                "isp": "EE",
                "match": [
                    "re:url:EEBodyRule"
                ]
            }
        ],
        "self-test": {
            "must-allow": [
                "http://must.allow.fakedomain"
            ],
            "must-block": [
                "http://must.block.fakedomain"
            ]
        },
        "version": "2018012301"
    }

    """

    mock_middleware_api = Mock(MiddlewareAPI)
    mock_middleware_api.config.return_value = json.loads(config)
    mock_middleware_api.status_ip.return_value = {"ip": "0.0.0.0", "isp": "EE"}

    monkeypatch.setattr(ProbeModule, 'MiddlewareAPI', lambda *args: mock_middleware_api)
    return mock_middleware_api


@pytest.fixture()
def mock_url_tester(monkeypatch):
    mock_url_tester = Mock(UrlTester)

    def test_url(rules_matcher, url):
        if "must.block.fakedomain" in url:
            return Result('blocked', 200)
        else:
            return Result('ok', 200)

    mock_url_tester.test_url.side_effect = test_url
    monkeypatch.setattr(ProbeModule, 'UrlTester', lambda *args: mock_url_tester)

    return mock_url_tester


def test_successful_check(mock_amqp_queue,
                          mock_middleware_api,
                          mock_url_tester,
                          mock_probe_config):
    probe = Probe(mock_probe_config)
    probe.run()

    mock_amqp_queue.callback({
        "url": "http://whatever",
        "hash": '',
        "request_id": "000"
    })

    report = mock_amqp_queue.queue.send.call_args[0]
    assert {
        'status': 'ok',
        'ssl_verified': None,
        'ip_network': '0.0.0.0',

        'probe_uuid': u'01234567890123456788',
        'blocktype': '',
        'network_name': 'EE',
        'category': '',
        'title': 'Google',
        'url': 'http://www.google.com',
        'ssl_fingerprint': None,
        'http_status': 200,
        'request_id': '000',
    } <= report


def test_selftest_successful(mock_amqp_queue,
                             mock_middleware_api,
                             mock_url_tester,
                             mock_probe_config):
    mock_probe_config.set('probe', 'selftest', 'True')
    probe = Probe(mock_probe_config)
    probe.run()


def test_selftest_blocked_site_allowed(mock_amqp_queue,
                                       mock_middleware_api,
                                       mock_url_tester,
                                       mock_probe_config):
    mock_url_tester.test_url.side_effect = None
    mock_url_tester.test_url.return_value = Result('ok', 200)

    mock_probe_config.set('probe', 'selftest', 'True')
    probe = Probe(mock_probe_config)
    with raises(SelfTestError):
        probe.run()


def test_selftest_allowed_site_blocked(mock_amqp_queue,
                                       mock_middleware_api,
                                       mock_url_tester,
                                       mock_probe_config):
    mock_url_tester.test_url.side_effect = None
    mock_url_tester.test_url.return_value = Result('blocked', 200)
    mock_probe_config.set('probe', 'selftest', 'True')
    probe = Probe(mock_probe_config)
    with raises(SelfTestError):
        probe.run()
