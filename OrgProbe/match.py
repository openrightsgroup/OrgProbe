
import re
import logging

from .result import Result

CHARSET = 'utf8'

class RulesMatcher(object):
    READ_SIZE = 8192
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
            if field == 'body':
                value = body
                flags = re.M

            match = re.search(
                    pattern, 
                    value if isinstance(value, str) else value.decode(CHARSET), 
                    flags)
            if match is not None:
                return True
            return False

        return None

    def test_response(self, req):
        category = ''
        if req.headers['content-type'].lower().startswith('text'):
            body = next(req.iter_content(self.READ_SIZE))
        else:
            # we're not downloading images
            body = ''
        logging.debug("Read body length: %s", len(body))
        #if self.counters:
        #    self.counters.bytes.add(len(body))
        for rulenum, rule in enumerate(self.rules):
            if self.match_rule(req, body, rule) is True:
                logging.info("Matched rule: %s; blocked", rule)
                if self.categorizor:
                    category = self.categorizor.categorize(req.url)
                return Result(
                    'blocked',
                    req.history[-1].status_code 
                        if hasattr(req, 'history') and len(req.history) > 0 
                        else req.status_code,
                    category,
                    self.blocktype[rulenum] if self.blocktype else None,
                    self.extract_title(body)
                )

            return Result('ok',  req.status_code, title=self.extract_title(body))

    def extract_title(self, content):
        match = re.search(b'<title>(.*?)</title', content, re.S+re.I+re.M)
        if match:
            return match.group(1).strip()
