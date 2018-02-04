import pytest

from os import path

from OrgProbe.result import Result
from OrgProbe.url_tester import UrlTester
from test.mock_server import tcp_server_that_times_out, http_server_that_returns_success, \
    https_server_that_returns_success, CERTIFICATE_FINGERPRINT


def build_url_tester(verify_ssl=False):
    url_tester = UrlTester({
        "secret": "secret",
        "verify_ssl": "false"
    })

    if verify_ssl:
        # This is a pretty nasty hack - only works because the
        # url_tester passes self.verify_ssl to requests.get, so
        # we can cheat and pass our cert rather than true.
        url_tester.verify_ssl = path.join(path.dirname(__file__),
                                          "ssl_certs/localhost.crt")

    return url_tester


@pytest.fixture
def rules_matcher():
    class MockRulesMatcher(object):
        def test_response(self, response):
            return Result('ok', 200, title="title", body_length=1234)

    return MockRulesMatcher()


def test_retrieve_not_existent(rules_matcher):
    result = build_url_tester().test_url(rules_matcher, 'http://does.not.exist.example.local')
    assert result.status == 'dnserror'
    assert result.code == -1
    assert result.ip is None


def test_retrieve_invalid(rules_matcher):
    result = build_url_tester().test_url(rules_matcher, 'bob')
    assert result.status == 'error'
    assert result.code == -1
    assert result.ip is None


def test_no_https(rules_matcher):
    with http_server_that_returns_success() as port:
        result = build_url_tester().test_url(rules_matcher, 'http://localhost:{}'.format(port))
        assert result.status == 'ok'
        assert result.code == 200
        assert result.ssl_verified is None
        assert result.ssl_fingerprint is None
        assert result.ip is not None


def test_https(rules_matcher):
    with https_server_that_returns_success() as port:
        result = build_url_tester().test_url(rules_matcher, 'https://localhost:{}/'.format(port))
        assert result.status == 'ok'
        assert result.code == 200
        assert not result.ssl_verified
        assert result.ssl_fingerprint == CERTIFICATE_FINGERPRINT


def test_https_with_verify_ssl(rules_matcher):
    with https_server_that_returns_success() as port:
        result = build_url_tester(verify_ssl=True).test_url(
            rules_matcher, 'https://localhost:{}/'.format(port))
        assert result.status == 'ok'
        assert result.code == 200
        assert result.ssl_verified
        assert result.ssl_fingerprint == CERTIFICATE_FINGERPRINT


def test_timeout(rules_matcher):
    with tcp_server_that_times_out() as port:
        result = build_url_tester().test_url(rules_matcher, 'http://localhost:{}'.format(port))
        assert result.status == 'timeout'
        assert result.code == -1
        assert result.ssl_verified is None
        assert result.ssl_fingerprint is None
