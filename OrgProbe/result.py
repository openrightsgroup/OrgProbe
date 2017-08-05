import json

class Result(object):
    __slots__ = ['status','code','category','type','title','ip']
    def __init__(self, status, code, category=None, type=None, title=None, ip=None):
        self.status = status
        self.code = code
        self.category = category
        self.type = type
        self.title = title
        self.ip = ip

    def __str__(self):
        return "<Result: " + (" ".join([
            "{}={}".format(k, getattr(self, k)) for k in self.__slots__
            ])) + ">"
