import unittest

from OrgProbe.match import RulesMatcher
from OrgProbe.category import Categorizor


class FakeRequest(object):
    def __init__(self, url, status_code, history=None):
        self.status_code = status_code
        self.url = url
        if history:
            self.history = history
        self.headers = {"content-type": "text/html; charset=utf-8"}
        self.iter_content = lambda x: ["test content <title>foo</title>"].__iter__()


class RulesTests(unittest.TestCase):
    TEST_REQ = FakeRequest(
        "http://www.talktalk.co.uk/notice/parental-controls?" +
        "accessurl=d3d3LnhoYW1zdGVyLmNvbQ==&" +
        "urlclassname=UG9ybm9ncmFwaHkgJiBWaW9sZW5jZQ==",
        200,
        [
            FakeRequest('http://naughtysite.com', 302)
        ]
    )

    def setUp(self):
        self.matcher = RulesMatcher([
            "re:url:^http://www\\.talktalk\\.co\\.uk/" +
            "notice/parental-controls\\?accessurl",
            "re:url:^http://www\\.siteblocked\\.org/piratebay\\.html\\?"
        ],
            ['PARENTAL', 'COPYRIGHT'],
            Categorizor('querystring:urlclassname:base64')
        )

    def testMatch(self):
        result = self.matcher.test_response(
            self.TEST_REQ)
        self.assertEquals(result.status, "blocked")
        self.assertEquals(result.code, 302)
        self.assertEquals(result.category, "Pornography & Violence")
        self.assertEquals(result.title, 'foo')
        self.assertEquals(result.type, 'PARENTAL')

    def testNoMatch(self):
        result = self.matcher.test_response(
            FakeRequest('http://example.com', 200))
        self.assertEquals(result.status, "ok")
        self.assertEquals(result.code, 200)
        self.assertIsNone(result.category)

    def testCopyrightMatch(self):
        result = self.matcher.test_response(
            FakeRequest('http://www.siteblocked.org/piratebay.html?', 200,
                        [FakeRequest('http://example.com', 302)]
                        )
        )
        self.assertEquals(result.status, "blocked")
        self.assertEquals(result.code, 302)
        self.assertIsNone(result.category)
        self.assertEquals(result.type, 'COPYRIGHT')
