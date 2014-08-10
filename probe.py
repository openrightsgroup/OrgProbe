
import os
import re
import sys
import json
import time
import logging
import requests
import hashlib
import contextlib

from api import *
from httpqueue import HTTPQueue
from signing import RequestSigner
from category import Categorizor

class SelfTestError(Exception):pass

class OrgProbe(object):
	DEFAULT_USERAGENT = 'OrgProbe/0.9.2 (+http://www.blocked.org.uk)'
	def __init__(self, config):
		self.config = config

		# initialize configuration

		# set up in .run()
		self.probe = None
		self.signer = None
		self.headers = {}
		self.read_size = 8192 # size of body to read

		# set up in .configure()

		self.apiconfig = None
		self.isp = None
		self.ip = None
		self.categorizor = None

		# set up in .setup_queue()
		self.hb = None
		pass

	def register(self, opts):
		logging.warning("Untested code")
		return
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
		if self.probe.get('api_config_file'):
			with open(self.probe['api_config_file']) as fp:
				self.apiconfig = json.load(fp)
				logging.info("Loaded config: %s from %s", self.apiconfig['version'], self.probe['api_config_file'])

			return
		req = ConfigRequest(None, self.probe.get('config_version','latest'))
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
		try:
			args = (self.probe['public_ip'],)
		except KeyError:
			args = []
		req = StatusIPRequest(self.signer, *args, probe_uuid=self.probe['uuid'] )
		code, data = req.execute()
		logging.info("Status: %s, %s", code, data)
		if 'network' in self.probe:
			self.isp = self.probe['network']
			logging.debug("Overriding network to: %s", self.isp)
		else:
			self.isp =  data['isp']

		self.ip = data['ip']

		for rule in self.apiconfig['rules']:
			if rule['isp'] == self.isp:
				self.rules = rule['match'] 
				if 'category' in rule:
					logging.info("Creating Categorizor with rule: %s", rule['category'])
					self.categorizor = Categorizor(rule['category'])
				break
		else:
			logging.error("No rules found for ISP: %s", self.isp)
			if self.probe.get('skip_rules','False') == 'True':
				self.rules = []
			else:
				sys.exit(1)

		logging.info("Got rules: %s", self.rules)

	def setup_queue(self):
		if not self.config.has_section('amqp'):
			logging.info("Using HTTP Queue")
			self.queue = HTTPQueue(self.probe['uuid'], self.signer, self.isp)
		else:
			from amqpqueue import AMQPQueue
			opts = dict(self.config.items('amqp'))
			logging.info("Setting up AMQP with options: %s", opts)
			self.queue = AMQPQueue(opts, 
				self.isp.lower().replace(' ','_'), 
				self.probe.get('queue', 'org'), 
				self.signer,
				int(self.probe['lifetime']) if 'lifetime' in self.probe else None 
				)
			if 'heartbeat' in self.probe:
				from heartbeat import Heartbeat
				self.hb = Heartbeat(self.queue.conn,
					int(self.probe['heartbeat']),
					self.probe['uuid']
					)
				self.hb.start_thread()

	def match_rule(self, req, body, rule):
		if rule.startswith('re:'):
			ruletype, field, pattern = rule.split(':',2)
			if field == 'url':
				value = req.url
				flags = 0
			if field == 'body':
				value = body
				flags = re.M

			match = re.search(pattern, value, flags)
			if match is not None:
				return True
			return False

		return None

	def test_response(self, req):
		category = ''
		if req.headers['content-type'].lower().startswith('text'):
			body = req.iter_content(self.read_size).next()
		else:
			# we're not downloading images
			body = ''
		logging.info("Read body length: %s", len(body))
		for rule in self.rules:
			if self.match_rule(req, body, rule) is True:
				logging.info("Matched rule: %s; blocked", rule)
				if self.categorizor:
					category = self.categorizor.categorize(req.url)
				return (
					'blocked', 
					req.history[-1].status_code if hasattr(req, 'history') and len(req.history) > 0 else req.status_code,
					category,
					)
		
		logging.info("Status: OK")
		return 'ok', req.status_code, None

	def test_url(self, url):
		logging.info("Testing URL: %s", url)
		try:
			with contextlib.closing(requests.get(url, headers=self.headers, timeout=5, stream=True)) as req:
				try:
					return self.test_response(req)
				except Exception,v:
					logging.error("Response test error: %s", v)
					raise
		except (requests.exceptions.Timeout,),v:
			logging.warn("Connection timeout: %s", v)
			return 'timeout', -1, None
		except Exception, v:
			logging.warn("Connection error: %s", v)
			return 'error', -1, None


	def test_and_report_url(self, url, urlhash = None):
		result, code, category = self.test_url(url)

		logging.info("Logging result with ORG: %s, %s", result, code)

		report = {
			'network_name': self.isp,
			'ip_network': self.ip,
			'url': url,
			'http_status': code,
			'status': result,
			'probe_uuid': self.probe['uuid'],
			'config': self.apiconfig['version'],
			'category': category or '',
		}

		self.queue.send(report, urlhash)


	def run_selftest(self):
		if self.probe.get('selftest', 'True')  == 'False':
			return
		
		for url in self.apiconfig['self-test']['must-allow']:
			if self.test_url(url)[0] != 'ok':
				raise SelfTestError
		for url in self.apiconfig['self-test']['must-block']:
			if self.test_url(url)[0] != 'blocked':
				raise SelfTestError
	

	def delay(self, multiplier=1):
		# only httpqueue requires sleep intervals at the moment
		if isinstance(self.queue, HTTPQueue):
			time.sleep(self.config.getint('global','interval') * multiplier)

	def run_test(self, data):
		if data is None:
			self.delay(5)
			return


		if 'url' in data:
			self.test_and_report_url(data['url'], data['hash'])
		elif 'urls' in data:
			for url in data['urls']:
				self.test_and_report_url(url['url'], data['hash'])

		self.delay()


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

		self.signer = RequestSigner(self.probe['secret'])
		self.headers = {
			'User-Agent': self.probe.get('useragent',self.DEFAULT_USERAGENT),
			}

		if 'read_size' in self.probe:
			self.read_size = int(self.probe['read_size'])

		self.configure()

		try:
			self.queue.drive(self.run_test)
			logging.info("Exiting cleanly")
		finally:
			if self.hb is not None:
				self.hb.stop_thread()


