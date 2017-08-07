import sys
import argparse
try:
    from ConfigParser import ConfigParser
except ImportError:
    from configparser import ConfigParser
import logging

from OrgProbe import Probe, APIRequest

parser = argparse.ArgumentParser()
parser.add_argument('--config', '-c', default='config.ini',
        help="path to config file")
parser.add_argument('--verbose', '-v', action='store_true', help="Verbose operation")
parser.add_argument(dest='profile', nargs='?')
args = parser.parse_args()

logging.basicConfig(
    level=logging.DEBUG if args.verbose else logging.INFO,
    datefmt='[%Y-%m-%d %H:%M:%S]',
    format='%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s')

logging.getLogger('urllib3.connectionpool').setLevel(logging.ERROR)
logging.getLogger('pika').setLevel(logging.ERROR)
logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.ERROR)

config = ConfigParser()
loaded = config.read([args.config])
logging.info("Loaded %s config files from %s", loaded, args.config)

if config.has_section('api'):
    def apiconfig(prop, method):
        try:
            setattr(APIRequest, prop.upper(), method('api', prop))
            logging.info("Set %s to %s", prop,
                         getattr(APIRequest, prop.upper()))
        except Exception:
            pass

    apiconfig('https', config.getboolean)
    apiconfig('host', config.get)
    apiconfig('port', config.getint)
    apiconfig('version', config.get)

probe = Probe(config)

logging.debug("Entering run mode")
sys.exit(probe.run(args))