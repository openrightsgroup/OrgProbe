import json

import logging

import amqplib.client_0_8 as amqp

class AMQPQueue(object):
	SIG_KEYS = ["probe_uuid", "url", "status", "date", "config"]
	def __init__(self, opts, network, public, signer):
		self.conn = amqp.Connection(
			user=opts['user'],
			passwd=opts['passwd'],
			host=opts['host']
			)
		self.network = network
		logging.debug("Opening AMQP connection")
		self.ch = self.conn.channel()
		self.signer = signer
		if public is False:
			self.queue_name = 'url.' + network + '.org'
		else:
			self.queue_name = 'url.'+network+'.public'
		logging.info("Listening on queue: %s", self.queue_name)

	def __iter__(self):
		while True:
			msg = self.ch.basic_get(self.queue_name)
			if msg is None:
				yield None
				continue
			data = json.loads(msg.body)
			logging.info("Got data: %s", data)
			self.ch.basic_ack(msg.delivery_tag)
			yield data

	def send(self, report, urlhash=None):

		report['date'] = self.signer.timestamp()
		report['signature'] = self.signer.get_signature(report, self.SIG_KEYS)

		msgbody = json.dumps(report)
		msg = amqp.Message(msgbody)
		key = 'results.'+self.network + ('.'+urlhash if urlhash is not None else '')
		logging.info("Sending result with key: %s", key)
		self.ch.basic_publish(msg,'org.blocked', key)

	def close(self):
		self.conn.close()
