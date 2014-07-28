
import unittest

from category import Categorizor
from probe import OrgProbe

class FakeRequest(object):
	def __init__(self, url, status_code, history = None):
		self.status_code = status_code
		self.url = url
		if history:
			self.history = history


class QueryStringCategorizorTests(unittest.TestCase):
	def setUp(self):
		pass

	def testCategory(self):
		categ = Categorizor('querystring:category')
		self.assertEquals('violence', 
			categ.categorize(
				'http://isp.example.com/blocked?category=violence'
				)
			)

	def testCategoryBase64(self):
		categ = Categorizor('querystring:category:base64')
		self.assertEquals('violence', 
			categ.categorize(
				'http://isp.example.com/blocked?category=dmlvbGVuY2U='
				)
			)

	def testCategoryMissing(self):
		categ = Categorizor('querystring:category')
		self.assertIsNone(
			categ.categorize(
				'http://isp.example.com/blocked'
				)
			)

class ProbeRulesTests(unittest.TestCase):
	TEST_REQ = FakeRequest(
		"http://www.talktalk.co.uk/notice/parental-controls?accessurl=d3d3LnhoYW1zdGVyLmNvbQ==&urlclassname=UG9ybm9ncmFwaHkgJiBWaW9sZW5jZQ==",
		200,
		[
			FakeRequest('http://naughtysite.com', 302)
		]
	)
	def setUp(self):
		self.probe = OrgProbe({})
		self.probe.rules = [
                "re:url:^http://www\\.talktalk\\.co\\.uk/notice/parental-controls\\?accessurl",
				"re:url:^http://www\\.siteblocked\\.org/piratebay\\.html\\?"
            ]
		self.probe.categorizor = Categorizor('querystring:urlclassname:base64')

	def testMatch(self):
		status, code, category = self.probe.test_response(self.TEST_REQ)
		self.assertEquals(status, "blocked")
		self.assertEquals(code, 302)
		self.assertEquals(category, "Pornography & Violence")

	def testNoMatch(self):
		status, code, category = self.probe.test_response(FakeRequest('http://example.com',200))
		self.assertEquals(status, "ok")
		self.assertEquals(code, 200)
		self.assertIsNone(category)
		

	

if __name__ == '__main__':
	unittest.main()

