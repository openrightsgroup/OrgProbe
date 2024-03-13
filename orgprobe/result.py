
import six

class Result(object):
    __slots__ = ['status', 'code', 'category', 'type', '_title', 'ip', 'body_length', 'ssl_verified',
                 'ssl_fingerprint', 'final_url', 'resolved_ip', 'request_data']

    def __init__(self,
                 status, code, category=None, type=None, title=None, ip=None,
                 body_length=0, ssl_verified=None, ssl_fingerprint=None, final_url=None, resolved_ip=None,
                 request_data=None):
        self.status = status
        self.code = code
        self.category = category
        self.type = type
        self._title = title
        self.ip = ip
        self.body_length = body_length
        self.ssl_verified = ssl_verified
        self.ssl_fingerprint = ssl_fingerprint
        self.final_url = final_url
        self.resolved_ip = resolved_ip
        self.request_data = request_data

    @property
    def title(self):
        return self._title

    def __str__(self):
        return "<Result: " + (" ".join([
            "{}=\"{}\"".format(k, getattr(self, k))
            for k in self.__slots__ + ['title']
            if k not in ('_title', 'request_data')
        ])) + ">"
