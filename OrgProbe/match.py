
import re
import logging

CHARSET = 'utf8'

class RulesMatcher(object):
    def __init__(self, rules, blocktype, categorizor, read_size):
        self.rules = rules
        self.blocktype = blocktype or []
        self.categorizor = categorizor
        self.read_size = read_size

    def match_rule(self, req, body, rule):
        if rule.startswith('re:'):
            ruletype, field, pattern = rule.split(':', 2)
            if field == 'url':
                value = req.url
                flags = 0
            if field == 'body':
                value = body
                flags = re.M

            print(type(pattern))
            print(type(value), value)
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
        if self.read_size > 0:
            if req.headers['content-type'].lower().startswith('text'):
                body = next(req.iter_content(self.read_size))
            else:
                # we're not downloading images
                body = ''
        else:
            body = req.content
        logging.debug("Read body length: %s", len(body))
        #if self.counters:
        #    self.counters.bytes.add(len(body))
        for rulenum, rule in enumerate(self.rules):
            if self.match_rule(req, body, rule) is True:
                logging.info("Matched rule: %s; blocked", rule)
                if self.categorizor:
                    category = self.categorizor.categorize(req.url)
                return (
                    'blocked',
                    req.history[-1].status_code if hasattr(req,
                                                           'history') and len(
                        req.history) > 0 else req.status_code,
                    category,
                    self.blocktype[rulenum] if self.blocktype else None
                )

        logging.info("Status: OK")
        return 'ok', req.status_code, None, None
