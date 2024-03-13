import re
import base64
import logging
import operator

from functools import reduce

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse


class Categorizor(object):
    def __init__(self, category_rule):
        """category_rule is a string of the format:
        type:parameter:modifier

        To get the base64 decoded value of the category querystring
        parameter, use:

        "querystring:category:base64"

        Regex match body with:

        <type>:<field>:<pattern>:<flags>
        re:body:foo bar (.*):m,i,x

        Flags are comma separated values from python re.RegexFlags
        """
        self.rule = category_rule.split(':')

    def categorize(self, final_url, body=None):
        if self.rule[0] == 'querystring':
            try:
                qs = urlparse.parse_qs(urlparse.urlparse(final_url).query)
                param = qs[self.rule[1]][0]
                if len(self.rule) == 3:
                    if self.rule[2] == 'base64':
                        param = base64.b64decode(param).decode('utf8')
                logging.debug("Got category: %s", param)
                return param
            except (KeyError, IndexError):
                return None
        if self.rule[0] == 're':
            if self.rule[1] == 'body':
                flags = self._get_flags()

                match = re.search(self.rule[2], body or '', flags)
                if match:
                    if match.groups():
                        return match.groups()[-1]

    def _get_flags(self):
        if len(self.rule) < 4:
            return 0
        parts = self.rule[3].upper().split(',')
        ret = reduce(operator.ior, [getattr(re, x) for x in parts if x], 0)
        return ret
