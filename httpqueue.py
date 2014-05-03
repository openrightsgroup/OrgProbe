
import logging
from api import RequestHttptRequest,ResponseHttptRequest

class HTTPQueue(object):
	def __init__(self, probe_uuid, signer, isp):
		self.probe_uuid, self.signer, self.isp = probe_uuid, signer, isp

	def __iter__(self):
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
		rsp = ResponseHttptRequest(self.signer,
		**report
		)
		rsp.execute()
