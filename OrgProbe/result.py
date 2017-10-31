class Result(object):
    __slots__ = ['status', 'code', 'category', 'type', '_title', 'ip', 'body_length', 'ssl_verified', 'ssl_fingerprint']

    def __init__(self,
                 status, code, category=None, type=None, title=None, ip=None,
                 body_length=0, ssl_verified=None, ssl_fingerprint=None):
        self.status = status
        self.code = code
        self.category = category
        self.type = type
        self._title = title
        self.ip = ip
        self.body_length = body_length
        self.ssl_verified = ssl_verified
        self.ssl_fingerprint = ssl_fingerprint

    @property
    def title(self):
        if self._title is None:
            return None
        if isinstance(self._title, unicode):
            return self._title.encode('utf8')
        # otherwise string; hope for utf8
        return self._title

    def __str__(self):
        return "<Result: " + (" ".join([
            "{}=\"{}\"".format(k, getattr(self, k))
            for k in self.__slots__ + ['title']
            if k not in ('_title',)
        ])) + ">"
