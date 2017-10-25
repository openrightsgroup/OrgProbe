import logging

import pytest
from OrgProbe.probe import Probe
from OrgProbe.match import RulesMatcher

from test.mock_server import tcp_server_that_times_out, http_server_that_returns_success, \
    https_server_that_returns_success

Probe.LOGGER.setLevel(logging.FATAL)


@pytest.fixture
def probe():
    probe = Probe({})
    probe.probe = {}
    probe.rules_matcher = RulesMatcher([], [], [])
    return probe


def test_retrieve_not_existent(probe):
    result = probe.test_url('http://does.not.exist.example.foobar')
    assert result.status == 'dnserror'
    assert result.code == -1
    assert result.ip is None


def test_retrieve_invalid(probe):
    result = probe.test_url('bob')
    assert result.status == 'error'
    assert result.code == -1
    assert result.ip is None


def test_no_https(probe):
    with http_server_that_returns_success() as port:
        result = probe.test_url('http://localhost:{}'.format(port))
        assert result.status == 'ok'
        assert result.code == 200
        assert result.ssl_verified is None
        assert result.ssl_fingerprint is None
        assert result.ip is not None


def test_https(probe):
    with https_server_that_returns_success() as port:
        result = probe.test_url('https://localhost:{}/'.format(port))
        assert result.status == 'ok'
        assert result.code == 200
        assert not result.ssl_verified
        assert result.ssl_fingerprint.startswith('55:71:61:C3')


def test_timeout(probe):
    with tcp_server_that_times_out() as port:
        result = probe.test_url('http://localhost:{}'.format(port))
        assert result.status == 'timeout'
        assert result.code == -1
        assert result.ssl_verified is None
        assert result.ssl_fingerprint is None
