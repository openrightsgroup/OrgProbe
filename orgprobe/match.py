import re
import logging

from .result import Result

CHARSET = 'utf8'


class RulesMatcher(object):
    def __init__(self, rules, blocktype, categorizor):
        self.rules = rules
        self.blocktype = blocktype or []
        self.categorizor = categorizor

    def match_rule(self, req, body, rule):
        if rule.startswith('re:'):
            ruletype, field, pattern = rule.split(':', 2)
            if field == 'url':
                value = req.url
                flags = 0
            elif field == 'body':
                value = body
                flags = re.M
            elif field.startswith('hdr.'):
                header = field.split('.', 1)[-1]
                if header not in req.headers:
                    logging.debug("Header %s not found, skipping", header)
                    return None
                value = req.headers[header]
                flags = 0
            else:
                logging.warn("unknown re test field: %s", field)
                return None

            match = re.search(
                pattern,
                value if isinstance(value, str) else value.decode(CHARSET),
                flags)
            if match is not None:
                return True
            return False

        return None

    def test_response(self, req, body):
        category = ''

        logging.debug("Read body length: %s", len(body))
        for rulenum, rule in enumerate(self.rules):
            if self.match_rule(req, body, rule) is True:
                logging.debug("Matched rule: %s; blocked", rule)
                if self.categorizor:
                    category = self.categorizor.categorize(req.url, body)
                return Result(
                    'blocked',
                    req.history[-1].status_code
                    if hasattr(req, 'history') and len(req.history) > 0
                    else req.status_code,
                    category,
                    self.blocktype[rulenum] if self.blocktype else None,
                    body_length=len(body)
                )

        return Result('ok', req.status_code, body_length=len(body))

