
import sys
import getopt
import ConfigParser
import logging

import requests

from api import APIRequest,StatusIPRequest
from signing import RequestSigner

optlist, optargs = getopt.getopt(sys.argv[1:],
    'c:v',
    ['register','email=','secret=','seed=']
    )
opts = dict(optlist)
logging.basicConfig(
    level = logging.DEBUG if '-v' in opts else logging.INFO,
    datefmt = '[%Y-%m-%d %H:%M:%S]',
    format='%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s')

logging.getLogger('urllib3.connectionpool').setLevel(logging.ERROR)
logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.ERROR)

configfile = opts.get('-c','config.ini')
config = ConfigParser.ConfigParser()
loaded = config.read([configfile])
logging.info("Loaded %s config files from %s", loaded, configfile)

if config.has_section('api'):
    def apiconfig(prop, method):
        try:
            setattr(APIRequest, prop.upper(), method('api',prop))
            logging.info("Set %s to %s", prop, getattr(APIRequest, prop.upper()))
        except Exception,v:
            pass

    apiconfig('https', config.getboolean)
    apiconfig('host', config.get)
    apiconfig('port', config.getint)
    apiconfig('version', config.get)

class AdminView(object):
    DEFAULT_USERAGENT = 'OrgProbe/0.9.4 (+http://www.blocked.org.uk)'

    def __init__(self, config):
        self.config = config
        self.signer = None
        self.ip = None
        self.isp = None
        self.headers = None

        pass


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

    def setup_queue(self):
        from amqpqueue import AMQPQueue
        opts = dict(self.config.items('amqp'))
        logging.info("Setting up AMQP with options: %s", opts)
        self.queue = AMQPQueue(opts, 
            self.isp.lower().replace(' ','_'), 
            self.probe.get('queue', 'org'), 
            self.signer,
            int(self.probe['lifetime']) if 'lifetime' in self.probe else None 
            )
        self.queue.queue_name = 'admin.view.' + self.isp.lower().replace(' ','_')

    def run_test(self, data):
        req = requests.get(data['url'])

        report = {
            'url': data['url'],
            'hash': data['hash'],
            'content': req.content,
            'network_name': self.isp,
            'ip_network': self.ip,
            'http_status': req.status_code,
            'status': 'ok',
            'probe_uuid': self.probe['uuid'],
            'config': -1,
            'category': '', 
            'blocktype': '',
            }

        self.queue.send(report, keyfunc=lambda: 'admin.results.{0}.{1}'.format(
            self.isp.lower().replace(' ','_'), data['hash']
            )
        )
            



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

        self.get_ip_status()
        self.setup_queue()

        try:
            self.queue.drive(self.run_test)
            logging.info("Exiting cleanly")
        finally:
            logging.info("Shutting down")

adminview = AdminView(config)

logging.info("Entering run mode")
sys.exit(adminview.run(optargs))
