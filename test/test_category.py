from orgprobe.category import Categorizor


def test_category():
    assert 'violence' == Categorizor('querystring:category').categorize(
        'http://isp.example.com/blocked?category=violence')


def test_category_base64():
    assert 'violence' == Categorizor('querystring:category:base64').categorize(
        'http://isp.example.com/blocked?category=dmlvbGVuY2U=')


def test_category_missing():
    assert None is Categorizor('querystring:category').categorize(
        'http://isp.example.com/blocked')


def test_category_body_capture():
    assert 'agency' == Categorizor('re:body:three letter (.*)').categorize('http://example.com', "three letter agency")


def test_category_body_nocapture():
    assert None is Categorizor('re:body:three letter .*').categorize('http://example.com', "three letter agency")


def test_category_body_nomatch():
    assert None is Categorizor('re:body:three letter (.*)').categorize('http://example.com', "four letter word")


def test_category_body_capture_flags():
    assert 'agency' == Categorizor('re:body:three letter (.*):i').categorize('http://example.com', "Three Letter agency")


def test_category_flags_undefined():
    flags = Categorizor('re:body:foo')._get_flags()
    assert flags == 0


def test_category_flags_empty():
    flags = Categorizor('re:body:foo:')._get_flags()
    assert flags == 0


def test_category_flags_nocase():
    import re
    flags = Categorizor('re:body:foo:i')._get_flags()
    assert flags == re.I


def test_category_flags_nocase_multi():
    import re
    flags = Categorizor('re:body:foo:i,m')._get_flags()
    assert flags == re.I|re.MULTILINE
