import logging
import unittest

import requests

from OrgProbe.match import RulesMatcher
from OrgProbe.probe import Probe
from tests.mock_server import tcp_server_that_times_out, http_server_that_returns_success, \
    https_server_that_returns_success

Probe.LOGGER.setLevel(logging.FATAL)


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.probe = Probe({})
        self.probe.probe = {}
        self.probe.rules_matcher = RulesMatcher([], [], [])
        # test that requests library is new enough
        self.requests_new = map(int, requests.__version__.split('.')) > [2, 12, 0]

    def testRetrieveNotExistent(self):
        result = self.probe.test_url('http://does.not.exist.example.foobar')
        self.assertEquals(result.status, 'dnserror')
        self.assertEquals(result.code, -1)
        if self.requests_new:
            self.assertEquals(result.ip, None)

    def testRetrieveInvalid(self):
        result = self.probe.test_url('bob')
        self.assertEquals(result.status, 'error')
        self.assertEquals(result.code, -1)
        if self.requests_new:
            self.assertEquals(result.ip, None)

    def testNoHTTPS(self):
        with http_server_that_returns_success() as port:
            result = self.probe.test_url('http://localhost:{}'.format(port))
            self.assertEquals(result.status, 'ok')
            self.assertEquals(result.code, 200)
            self.assertEquals(result.ssl_verified, None)
            self.assertEquals(result.ssl_fingerprint, None)
            if self.requests_new:
                self.assertNotEquals(result.ip, None)

    def testHTTPS(self):
        with https_server_that_returns_success() as port:
            result = self.probe.test_url('https://localhost:{}/'.format(port))
            self.assertEquals(result.status, 'ok')
            self.assertEquals(result.code, 200)
            self.assertEquals(result.ssl_verified, False)
            self.assertNotEquals(result.ssl_fingerprint, None)

    def testTimeout(self):
        with tcp_server_that_times_out() as port:
            result = self.probe.test_url('http://localhost:{}'.format(port))
            self.assertEquals(result.status, 'timeout')
            self.assertEquals(result.code, -1)
            self.assertEquals(result.ssl_verified, None)
            self.assertEquals(result.ssl_fingerprint, None)
