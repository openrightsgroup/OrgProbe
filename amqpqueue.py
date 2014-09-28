import json

import logging

import amqplib.client_0_8 as amqp

class AMQPQueue(object):
	SIG_KEYS = ["probe_uuid", "url", "status", "date", "config"]

	def __init__(self, opts, network, queue_name, signer, lifetime = None):
		self.conn = amqp.Connection(
			userid=opts['userid'],
			password=opts['passwd'],
			host=opts['host']
			)
		self.network = network
		logging.debug("Opening AMQP connection")
		self.ch = self.conn.channel()
		self.signer = signer
		self.queue_name = 'url.' + network + '.' + queue_name
		logging.info("Listening on queue: %s", self.queue_name)
		self.lifetime = lifetime
		self.alive = True
		self.count = 0

	def __iter__(self):
		"""The Queue object can be used as an iterator, to fetch a test URL from 
		the API."""

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
		"""Sends a report back to the server"""

		report['date'] = self.signer.timestamp()
		report['signature'] = self.signer.get_signature(report, self.SIG_KEYS)

		msgbody = json.dumps(report)
		msg = amqp.Message(msgbody)
		key = 'results.'+self.network + ('.'+urlhash if urlhash is not None else '')
		logging.info("Sending result with key: %s", key)
		self.ch.basic_publish(msg,'org.blocked', key)

	def drive(self, callback):
		""" This allows the queue to drive testing, by passing each
		data item that is fetched from the API to a callback function."""

		def decode(msg):
			# this is a wrapper callback that decodes the json data
			# before passing it to the probe's real callback
			data = json.loads(msg.body)
			logging.info("Got data: %s", data)
			self.ch.basic_ack(msg.delivery_tag)
			callback(data)
			self.count += 1
			logging.debug("Count: %s, Lifetime: %s", self.count, self.lifetime)
			if self.lifetime is not None and self.count > self.lifetime:
				logging.info("Cancelling subscription due to lifetime expiry")
				self.alive = False
		if 'prefetch' in opts:
			logging.debug("Setting QOS prefetch to %s", opts['prefetch'])	
			self.ch.basic_qos(0, int(opts['prefetch']))
		self.ch.basic_consume(self.queue_name, consumer_tag='consumer1', callback=decode)
		while self.alive:
			# loop while alive, pumping messages
			self.ch.wait()


	def close(self):
		self.conn.close()
