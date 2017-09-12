
from OrgProbe.probe import Probe
from OrgProbe.match import RulesMatcher

import unittest
import logging
import requests

Probe.LOGGER.setLevel(logging.FATAL)


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.probe = Probe({})
        self.probe.probe = {}
        self.probe.rules_matcher = RulesMatcher([],[],[])

        # test that requests library is new enough
        self.requests_new = map(int, requests.__version__.split('.')) > [2,12,0]

    def testRetrieveNotExistant(self):

        result = self.probe.test_url('http://does.not.exist.example.com')
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

        result = self.probe.test_url('http://test99.dretzq.co.uk')
        self.assertEquals(result.status, 'ok')
        self.assertEquals(result.code, 200)
        self.assertEquals(result.ssl_verified, None)
        self.assertEquals(result.ssl_fingerprint, None)
        if self.requests_new:
            self.assertNotEquals(result.ip, None)

    def testHTTPS(self):

        result = self.probe.test_url('https://www.dretzq.org.uk')
        self.assertEquals(result.status, 'ok')
        self.assertEquals(result.code, 200)
        self.assertEquals(result.ssl_verified, False)
        self.assertNotEquals(result.ssl_fingerprint, None)

    def testTimeout(self):
        # iptables -I INPUT -p tcp --dport 8002 -j DROP

        result = self.probe.test_url('http://localhost:8002')
        self.assertEquals(result.status, 'timeout')
        self.assertEquals(result.code, -1)
        self.assertEquals(result.ssl_verified, None)
        self.assertEquals(result.ssl_fingerprint, None)


