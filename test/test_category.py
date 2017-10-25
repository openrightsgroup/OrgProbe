from OrgProbe.category import Categorizor


def test_category():
    assert 'violence' == Categorizor('querystring:category').categorize(
        'http://isp.example.com/blocked?category=violence')


def test_category_base64():
    assert 'violence' == Categorizor('querystring:category:base64').categorize(
        'http://isp.example.com/blocked?category=dmlvbGVuY2U=')


def test_category_missing():
    assert None is Categorizor('querystring:category').categorize(
        'http://isp.example.com/blocked')
