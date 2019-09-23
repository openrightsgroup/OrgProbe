# coding: utf-8
from orgprobe.result import Result

import logging

TEST_UUID = '5c0cd5bc-c8b5-4a7e-a324-37791b019ee2'

def test_unicode():
    title = u"Some text here with a \u00a3 sign"
    r = Result('ok', 200, title=title)
    r.test_uuid = TEST_UUID

    assert isinstance(title, unicode)
    assert r.title == "Some text here with a £ sign"
    assert isinstance(r.title, str)
    assert str(r) == """<Result: status="ok" code="200" category="None" type="None" ip="None" body_length="0" """ \
        """ssl_verified="None" ssl_fingerprint="None" final_url="None" resolved_ip="None" test_uuid="5c0cd5bc-c8b5-4a7e-a324-37791b019ee2" title="Some text here with a £ sign">"""
    logging.info("result: %s", r)


def test_utf8():
    r = Result('ok', 200, title="£20")
    r.test_uuid = TEST_UUID

    assert r.title == "£20"
    assert isinstance(r.title, str)
    assert str(r) == """<Result: status="ok" code="200" category="None" type="None" ip="None" body_length="0" """ \
        """ssl_verified="None" ssl_fingerprint="None" final_url="None" resolved_ip="None" test_uuid="5c0cd5bc-c8b5-4a7e-a324-37791b019ee2" title="£20">"""
