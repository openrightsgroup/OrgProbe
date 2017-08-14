
from OrgProbe.probe import Probe

import unittest

class ProbeTests(unittest.TestCase):
    def testRetrieve(self):
        probe = Probe({})

        result = probe.test_url('http://does.not.exist.example.com')
        self.assertEquals(result.status, 'dnserror')
        self.assertEquals(result.code, -1)
        
