from orgprobe.category import Categorizor

from orgprobe.match import RulesMatcher


class FakeRequest(object):
    SAMPLETITLE = "test content <title>foo</title>"
    def __init__(self, url, status_code, history=None):
        self.status_code = status_code
        self.url = url
        if history:
            self.history = history
        self.headers = {"content-type": "text/html; charset=utf-8"}
        self.iter_content = lambda x: [self.SAMPLETITLE].__iter__()


matcher = RulesMatcher(
    [
        "re:url:^http://www\\.talktalk\\.co\\.uk/notice/parental-controls\\?accessurl",
        "re:url:^http://www\\.siteblocked\\.org/piratebay\\.html\\?"
    ],
    ['PARENTAL', 'COPYRIGHT'],
    Categorizor('querystring:urlclassname:base64')
)


def test_match():
    result = matcher.test_response(
        FakeRequest(
            ("http://www.talktalk.co.uk/notice/parental-controls?accessurl=d3d3LnhoYW1zdGVyLmNvbQ=="
             "&urlclassname=UG9ybm9ncmFwaHkgJiBWaW9sZW5jZQ=="),
            200,
            [
                FakeRequest('http://naughtysite.com', 302)
            ]
        ), FakeRequest.SAMPLETITLE)
    assert result.status == "blocked"
    assert result.code == 302
    assert result.category == "Pornography & Violence"
    assert result.type == 'PARENTAL'


def test_no_match():
    result = matcher.test_response(
        FakeRequest('http://example.com', 200), '')
    assert result.status == "ok"
    assert result.code == 200
    assert result.category is None


def test_copyright_match():
    result = matcher.test_response(
        FakeRequest('http://www.siteblocked.org/piratebay.html?',
                    200,
                    [FakeRequest('http://example.com', 302)]),
                    '')
    assert result.status == "blocked"
    assert result.code == 302
    assert result.category is None
    assert result.type == 'COPYRIGHT'
