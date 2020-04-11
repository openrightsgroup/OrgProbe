import pytest

from os import path

from orgprobe.result import Result
from orgprobe.url_tester import UrlTester
from test.mock_server import tcp_server_that_times_out, http_server_that_returns_success, \
    https_server_that_returns_success, CERTIFICATE_FINGERPRINT


@pytest.fixture
def url_tester(mock_rules_matcher):
    def build(verify_ssl=False):
        url_tester = UrlTester(
            probe_config={
                "secret": "secret",
                "verify_ssl": "false",
                "record_requests": "true"
            },
            counters=None,
            rules_matcher=mock_rules_matcher
        )

        if verify_ssl:
            # This is a pretty nasty hack - only works because the
            # url_tester passes self.verify_ssl to requests.get, so
            # we can cheat and pass our cert rather than true.
            url_tester.verify_ssl = path.join(path.dirname(__file__),
                                              "ssl_certs/localhost.crt")

        return url_tester
    return build


@pytest.fixture
def mock_rules_matcher():
    class MockRulesMatcher(object):
        def test_response(self, response, body):
            return Result('ok', 200, title="title", body_length=1234)

    return MockRulesMatcher()


def test_retrieve_not_existent(url_tester):
    result = url_tester().test_url('http://does.not.exist.example.local')
    assert result.status == 'dnserror'
    assert result.code == -1
    assert result.ip is None


def test_retrieve_invalid(url_tester):
    result = url_tester().test_url('bob')
    assert result.status == 'error'
    assert result.code == -1
    assert result.ip is None


def test_image(url_tester):
    with http_server_that_returns_success() as port:
        result = url_tester().test_url('http://localhost:{}/image.png'.format(port))

        # requests for non-text MIME types should not retrieve payload or log content & digest

        assert result.status == 'ok'
        assert result.code == 200
        assert result.request_data[-1]['rsp']['content'] is None
        assert result.request_data[-1]['rsp']['hash'] is None

def test_redirect(url_tester):
    with http_server_that_returns_success() as port:
        result = url_tester().test_url('http://localhost:{}/redir'.format(port))

        assert result.status == 'ok'
        assert result.code == 200

        assert len(result.request_data) == 2
        assert result.request_data[0]['rsp']['ip'] is not None
        assert result.request_data[0]['rsp']['content'] == "Redirecting to /"
        assert result.request_data[0]['rsp']['hash'] == "f323a65c61122546e7f910891dfdff4f7f3c9215885982bb61b39fa1039763e0"

        assert result.request_data[1]['rsp']['ip'] is not None
        assert result.request_data[1]['rsp']['ssl_fingerprint'] is None
        assert result.request_data[1]['rsp']['ssl_verified'] is None
        assert result.request_data[1]['rsp']['hash'] == "0a0ba88b1efe73e8915aa4c6b6197f70d51f8bdf1fdc3ecb54d50b55f3d29d61"

def test_no_https(url_tester):
    with http_server_that_returns_success() as port:
        result = url_tester().test_url('http://localhost:{}'.format(port))
        assert result.status == 'ok'
        assert result.code == 200
        assert result.ssl_verified is None
        assert result.ssl_fingerprint is None
        assert result.ip is not None

        assert result._title == "Title Text"

        # result recording
        assert len(result.request_data) > 0
        assert result.request_data[0]['rsp']['ip'] is not None
        assert result.request_data[0]['rsp']['ssl_fingerprint'] is None
        assert result.request_data[0]['rsp']['ssl_verified'] is None
        assert result.request_data[0]['rsp']['hash'] == "0a0ba88b1efe73e8915aa4c6b6197f70d51f8bdf1fdc3ecb54d50b55f3d29d61"
        assert result.request_data[0]['rsp']['content'] == """<html>
<head>
<title>Title Text</title>
</head>
<body>
<h1>Hello!</h1>
</body>
</html>
"""


@pytest.mark.filterwarnings('ignore:Unverified HTTPS request is being made')
def test_https(url_tester):
    with https_server_that_returns_success() as port:
        result = url_tester().test_url('https://localhost:{}/'.format(port))
        assert result.status == 'ok'
        assert result.code == 200
        assert not result.ssl_verified
        assert result.ssl_fingerprint == CERTIFICATE_FINGERPRINT

        # result recording
        assert len(result.request_data) > 0
        assert result.request_data[0]['rsp']['ip'] is not None
        assert result.request_data[0]['rsp']['ssl_fingerprint'] is not None
        assert result.request_data[0]['rsp']['ssl_verified'] is not None


@pytest.mark.filterwarnings('ignore:Certificate for localhost has no `subjectAltName`')
def test_https_with_verify_ssl(url_tester):
    with https_server_that_returns_success() as port:
        result = url_tester(verify_ssl=True).test_url(
            'https://localhost:{}/'.format(port))
        assert result.status == 'ok'
        assert result.code == 200
        assert result.ssl_verified
        assert result.ssl_fingerprint == CERTIFICATE_FINGERPRINT

        # result recording
        assert len(result.request_data) > 0
        assert result.request_data[0]['rsp']['ip'] is not None
        assert result.request_data[0]['rsp']['ssl_fingerprint'] == CERTIFICATE_FINGERPRINT
        assert result.request_data[0]['rsp']['ssl_verified'] is True


def test_timeout(url_tester):
    with tcp_server_that_times_out() as port:
        result = url_tester().test_url('http://localhost:{}'.format(port))
        assert result.status == 'timeout'
        assert result.code == -1
        assert result.ssl_verified is None
        assert result.ssl_fingerprint is None
