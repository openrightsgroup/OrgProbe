
import logging
from api import RequestHttptRequest,ResponseHttptRequest

class HTTPQueue(object):
	def __init__(self, probe_uuid, secret, isp):
		self.probe_uuid, self.secret, self.isp = probe_uuid, secret, isp

	def __iter__(self):
		while True:
			rq = RequestHttptRequest(self.secret, 
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

	def send(self, report):
		rsp = ResponseHttptRequest(self.secret,
		**report
		)
		rsp.execute()
