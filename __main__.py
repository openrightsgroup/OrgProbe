
import sys
import getopt
import ConfigParser
import logging

from probe import OrgProbe
from api import APIRequest

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

if not config.has_section('global'):
	config.add_section('global')
	config.set('global','interval',1)
	with open(configfile,'w') as fp:
		config.write(fp)

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

probe = OrgProbe(config)

if '--register' in opts:
	probe.register(opts, config)
	with open(configfile,'w') as fp:
		config.write(fp)
	sys.exit(0)

else:
	logging.info("Entering run mode")
	sys.exit(probe.run(optargs))
