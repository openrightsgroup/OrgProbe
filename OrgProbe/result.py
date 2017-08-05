import json

class Result(object):
    __slots__ = ['status','code','category','type','title','ip','body_length']
    def __init__(self, status, code, category=None, type=None, title=None, ip=None, body_length=0):
        self.status = status
        self.code = code
        self.category = category
        self.type = type
        self.title = title
        self.ip = ip
        self.body_length = body_length

    def __str__(self):
        return "<Result: " + (" ".join([
            "{}={}".format(k, getattr(self, k)) for k in self.__slots__
            ])) + ">"
