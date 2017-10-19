import unittest

from OrgProbe.category import Categorizor


class QueryStringCategorizorTests(unittest.TestCase):
    def setUp(self):
        pass

    def testCategory(self):
        categ = Categorizor('querystring:category')
        self.assertEquals(
            'violence',
            categ.categorize('http://isp.example.com/blocked?'
                             'category=violence'))

    def testCategoryBase64(self):
        categ = Categorizor('querystring:category:base64')
        self.assertEquals(
            'violence',
            categ.categorize('http://isp.example.com/blocked?'
                             'category=dmlvbGVuY2U='))

    def testCategoryMissing(self):
        categ = Categorizor('querystring:category')
        self.assertIsNone(
            categ.categorize(
                'http://isp.example.com/blocked'))
