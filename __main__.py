
import sys
import getopt
import ConfigParser
import logging
import socket
import fcntl
import struct
import httplib

from probe import OrgProbe
from api import APIRequest

def get_ip_address(ifname):
    # Return the IP address for a given interface name

    # Create a new socket object using IPv4 address family and UDP protocol
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(                # Return the unpacked dotted-quad notation of...
        fcntl.ioctl(                        # the results of a system ioctl call that...
        s.fileno(),                         # using the file descriptor of the socket created above...
        0x8915,                             # calls the C function SIOCGIFADDR to get an interface address...
        struct.pack('256s', ifname[:15])    # passing to it the interface name, truncated to 15 characters, packed into single 256-byte string.
        )[20:24])                           # Limit what is returned to just those bytes from the response in which the IP address is contained.

optlist, optargs = getopt.getopt(sys.argv[1:],
	'c:v',
	['register','email=','secret=','seed=']
	)
opts = dict(optlist)
logging.basicConfig(
	level = logging.DEBUG if '-v' in opts else logging.INFO,
	datefmt = '[%Y-%m-%d %H:%M:%S]',
	format='%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s')

#logging.getLogger('urllib3.connectionpool').setLevel(logging.ERROR)
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

try:
    iface = config.get('global','interface')
    sourceIP = get_ip_address(iface)

    # Monkey patch httplib to make it source-address aware
    HTTPSConnection_real = httplib.HTTPSConnection
    class HTTPSConnection_monkey(HTTPSConnection_real):
        def __init__(*a, **kw):
            HTTPSConnection_real.__init__(*a, source_address=(sourceIP, 0), **kw)
    httplib.HTTPSConnection = HTTPSConnection_monkey
    logging.info("Using network interface %s (%s)", iface, sourceIP)
except ConfigParser.NoOptionError:
    logging.info("Network interface not configured - using system default")
except IOError:
    logging.info("Configured network interface " + iface + " does not exist - using system default")

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
