
from OrgProbe.probe import Probe

import unittest
import logging
#logging.basicConfig(level=logging.DEBUG)

class ProbeTests(unittest.TestCase):
    def testRetrieveNotExistant(self):
        probe = Probe({})
        probe.probe = {}

        result = probe.test_url('http://does.not.exist.example.com')
        self.assertEquals(result.status, 'dnserror')
        self.assertEquals(result.code, -1)
        
