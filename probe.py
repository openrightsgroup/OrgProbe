
import os
import re
import sys
import json
import time
import logging
import requests
import hashlib

from api import *
from httpqueue import HTTPQueue

class SelfTestError(Exception):pass

class OrgProbe(object):
	def __init__(self, config):
		self.config = config
		self.apiconfig = None
		self.isp = None
		self.ip = None
		self.probe = None
		pass

	def register(self, opts):
		req = PrepareProbeRequest(opts['--secret'], email=opts['--email'])
		code, data = req.execute()

		print code, data

		if data['success'] is not True:
			logging.error("Unable to prepare probe: %s", data)
			return

		probe_uuid = hashlib.md5(opts['--seed']+'-'+data['probe_hmac']).hexdigest()
		req2 = RegisterProbeRequest(opts['--secret'], email=opts['--email'],
			probe_seed=opts['--seed'],
			probe_uuid=probe_uuid
			)
		code2,data2 = req2.execute()
		print code2,data2

		if data2['success'] is not True:
			logging.error("Unable to prepare probe: %s", data2)
			return

		self.config.add_section(opts['--seed'])
		self.config.set(opts['--seed'], 'uuid', probe_uuid)
		self.config.set(opts['--seed'], 'secret', data2['secret'])

	def configure(self):
		self.get_api_config()
		self.get_ip_status()
		self.run_selftest()
		self.setup_queue()
		
	def get_api_config(self):
		req = ConfigRequest(None)
		code, data = req.execute()
		if code == 200:
			logging.info("Loaded config: %s", data['version'])
			self.apiconfig = data
			print >>sys.stderr, data
		elif code == 304:
			pass
		else:
			logging.error("Error downloading config: %s, %s", code, data['error'])

	def get_ip_status(self):
		req = StatusIPRequest(self.probe['secret'], probe_uuid=self.probe['uuid'] )
		code, data = req.execute()
		logging.info("Status: %s, %s", code, data)
		self.isp =  data['isp']
		self.ip = data['ip']

		for rule in self.apiconfig['rules']:
			if rule['isp'] == self.isp:
				self.rules = rule['match'] 
				break
		else:
			logging.error("No rules found for ISP: %s", self.isp)
			sys.exit(1)
		logging.info("Got rules: %s", self.rules)

	def setup_queue(self):
		if not self.config.has_section('amqp'):
			logging.info("Using HTTP Queue")
			self.queue = HTTPQueue(self.probe['uuid'], self.probe['secret'], self.isp)
		else:
			from amqpqueue import AMQPQueue
			opts = dict(self.config.items('amqp'))
			logging.info("Setting up AMQP with options: %s", opts)
			self.queue = AMQPQueue(opts, self.isp.lower().replace(' ','_'), self.probe.get('public', False) is True)


	def match_rule(self, req, rule):
		if rule.startswith('re:'):
			ruletype, field, pattern = rule.split(':',2)
			if field == 'url':
				value = req.url

			match = re.search(pattern, value)
			if match is not None:
				return True
			return False

		return None
				

	def test_url(self, url):
		logging.info("Testing URL: %s", url)
		try:
			req = requests.get(url, timeout=5)
		except (requests.exceptions.Timeout,),v:
			logging.warn("Connection timeout: %s", v)
			return 'timeout', -1
		except Exception, v:
			logging.warn("Connection error: %s", v)
			return 'error', -1

		for rule in self.rules:
			if self.match_rule(req, rule) is True:
				logging.info("Matched rule: %s; blocked", rule)
				return 'blocked', req.history[-1].status_code if hasattr(req, 'history') else req.status_code
		
		logging.info("Status: OK")
		return 'ok', req.status_code

	def test_and_report_url(self, url, urlhash = None):
		result, code = self.test_url(url)

		logging.info("Logging result with ORG: %s, %s", result, code)

		report = {
			'network_name': self.isp,
			'ip_network': self.ip,
			'url': url,
			'http_status': code,
			'status': result,
			'probe_uuid': self.probe['uuid'],
			'config': self.apiconfig['version'],
		}

		self.queue.send(report, urlhash)


	def run_selftest(self):
		try:
			if self.config.getboolean('global','selftest') is False:
				return
		except:
			pass
		
		for url in self.apiconfig['self-test']['must-allow']:
			if self.test_url(url)[0] != 'ok':
				raise SelfTestError
		for url in self.apiconfig['self-test']['must-block']:
			if self.test_url(url)[0] != 'blocked':
				raise SelfTestError
	

	def run(self, args):
		if len(args) > 0:
			self.probename = args[0]
		else:
			try:
				self.probename = [x for x in self.config.sections() if x not in ('amqp','api','global')][0]
			except IndexError:
				logging.error("No probe identity configuration found")
				return 1

		logging.info("Using probe: %s", self.probename)

		self.probe = dict([(x, self.config.get(self.probename,x)) 
			for x in self.config.options(self.probename)
			])

		self.configure()


		for data in self.queue:
			if data is None:
				time.sleep(self.config.getint('global','interval')*5)
				continue


			if 'url' in data:
				self.test_and_report_url(data['url'], data['hash'])
			elif 'urls' in data:
				for url in data['urls']:
					self.test_and_report_url(url['url'], data['hash'])



			time.sleep(self.config.getint('global','interval'))

