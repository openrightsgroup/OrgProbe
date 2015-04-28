
import logging
import redis


class OverLimitException(Exception): pass

class Counter(object):
	def __init__(self, r, network_name, name):
		self.r = r
		self.name = network_name + '.' + name
		self.value = self.get()

	def add(self, amount):
		self.value = self.r.incr(self.name, amount)

	def get(self):
		return self.r.get(self.name)

	def reset(self):
		self.r.set(self.name,0)


class Accounting(object):
	def __init__(self, config, network):
		self.r = redis.StrictRedis(config.get('accounting','redis_server'))
		self.config = config
		self.network = network

		self.r.sadd('networks',network)

		self.bytes = Counter(self.r, network, 'bytes_recv')
		self.requests = Counter(self.r, network, 'requests')

	def check(self):
		try:
			if self.config.getint('accounting','limit') < int(self.bytes.value):
				logging.fatal("Byte count is over limit: %d; shutting down", int(self.bytes.value))
				raise OverLimitException
		except OverLimitException:
			raise
		except Exception,v:
			logging.warn("Limit check exception: %s", repr(v))
			pass

	
