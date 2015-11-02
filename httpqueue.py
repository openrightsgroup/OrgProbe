import logging
from api import RequestHttptRequest, ResponseHttptRequest


class HTTPQueue(object):
    def __init__(self, probe_uuid, signer, isp):
        self.probe_uuid, self.signer, self.isp = probe_uuid, signer, isp

    def __iter__(self):
        """The Queue object can be used as an iterator, to fetch a test URL
        from the API."""
        while True:
            rq = RequestHttptRequest(self.signer,
                                     probe_uuid=self.probe_uuid,
                                     network_name=self.isp
                                     )
            code, data = rq.execute()
            if code == 404:
                yield None
            if code != 200:
                logging.error("Error getting URLs: %s", data)
                yield None

            yield data

    def send(self, report, urlhash=None):
        """Sends a report back to the server"""
        rsp = ResponseHttptRequest(self.signer,
                                   **report
                                   )
        rsp.execute()

    def drive(self, callback):
        """This allows the queue to drive testing, by passing each
        data item that is fetched from the API to a callback function."""
        for data in self:
            callback(data)
