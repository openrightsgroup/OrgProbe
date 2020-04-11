# coding: utf-8
from orgprobe.result import Result

import logging


def test_unicode():
    title = u"Some text here with a \u00a3 sign"
    r = Result('ok', 200, title=title)

    assert isinstance(title, unicode)
    assert r.title == "Some text here with a £ sign"
    assert isinstance(r.title, str)
    assert str(r) == """<Result: status="ok" code="200" category="None" type="None" ip="None" body_length="0" """ \
        """ssl_verified="None" ssl_fingerprint="None" final_url="None" resolved_ip="None" title="Some text here with a £ sign">"""
    logging.info("result: %s", r)


def test_utf8():
    r = Result('ok', 200, title="£20")

    assert r.title == "£20"
    assert isinstance(r.title, str)
    assert str(r) == """<Result: status="ok" code="200" category="None" type="None" ip="None" body_length="0" """ \
        """ssl_verified="None" ssl_fingerprint="None" final_url="None" resolved_ip="None" title="£20">"""
