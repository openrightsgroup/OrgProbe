import json
import datetime

import pytest
from mock import Mock
from pytest import raises

from orgprobe.amqpqueue import AMQPQueue
from orgprobe.probe import Probe, SelfTestError
from orgprobe.result import Result
from orgprobe.url_tester import UrlTester


@pytest.fixture
def mock_probe_config():
    return {
        'uuid': '01234567890123456788',
        'secret': 'secret',
        'queue': 'org',
        'selftest': 'False'
    }


@pytest.fixture
def mock_api_config():
    return json.loads("""
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
    """)


@pytest.fixture
def mock_amqp_queue():
    return Mock(AMQPQueue)


@pytest.fixture()
def mock_url_tester():
    mock_url_tester = Mock(UrlTester)

    def test_url(url):
        if "must.block.fakedomain" in url:
            return Result('blocked', 200)
        else:
            return Result('ok', 200)

    mock_url_tester.test_url.side_effect = test_url
    return mock_url_tester


@pytest.fixture
def probe(mock_amqp_queue,
          mock_api_config,
          mock_url_tester,
          mock_probe_config):
    return lambda: Probe(
        url_tester=mock_url_tester,
        queue=mock_amqp_queue,
        isp="FakeISP",
        ip="1.2.3.4",
        probe_config=mock_probe_config,
        apiconfig=mock_api_config)


def test_successful_check(mock_amqp_queue, probe):
    probe().run_test({
        "url": "http://whatever",
        "hash": '',
        "request_id": "000"
    })

    report = mock_amqp_queue.send_report.call_args[0][0]
    assert report['status'] == 'ok'
    assert report['request_id'] == '000'



def test_initial_selftest_successful(probe,
                                     mock_probe_config):
    mock_probe_config['selftest'] = 'True'

    probe().run_startup_selftest()


def test_initial_selftest_must_block_site_allowed(probe,
                                                  mock_url_tester,
                                                  mock_probe_config):
    mock_url_tester.test_url.side_effect = None
    mock_url_tester.test_url.return_value = Result('ok', 200)
    mock_probe_config['selftest'] = 'True'

    with raises(SelfTestError):
        probe().run_startup_selftest()


def test_initial_selftest_must_allow_site_blocked(probe,
                                                  mock_url_tester,
                                                  mock_probe_config):
    mock_url_tester.test_url.side_effect = None
    mock_url_tester.test_url.return_value = Result('blocked', 200)
    mock_probe_config['selftest'] = 'True'

    with raises(SelfTestError):
        probe().run_startup_selftest()

def test_jitter_func(mocker, monkeypatch, probe):

    probe_instance = probe()
    monkeypatch.setattr(Probe, '_get_timestamp',
                        staticmethod(lambda: datetime.datetime(2021, 6, 20, 11, 20, 0))
                        )

    sleeper = mocker.patch("time.sleep")
    probe_instance._jitter_delay({'submitted': '2021-06-20T11:19:59', 'jitter': True})
    assert sleeper.called

    sleeper = mocker.patch("time.sleep")
    probe_instance._jitter_delay({'submitted': '2021-06-20T11:19:59', 'jitter': False})
    assert not sleeper.called

    sleeper = mocker.patch("time.sleep")
    probe_instance._jitter_delay({'submitted': '2021-06-20T11:15:00', 'jitter': True})
    assert not sleeper.called
