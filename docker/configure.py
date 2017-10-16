
import os
import sys
import argparse
import ConfigParser

REQUIRED = [
    "PROBE_UUID", "PROBE_SECRET", "AMQP_USER", "AMQP_PASSWD"
]

DEFAULTS = {
    'API_HOST': 'api.blocked.org.uk',
    'API_PORT': '443',
    'API_HTTPS': 'True'
}


def envget(key):
    return env.get(key, DEFAULTS.get(key, None))


env = os.environ

parser = argparse.ArgumentParser(description="Script to write OrgProbe config file")
parser.add_argument('--output', '-o', help="Path to output file")
parser.add_argument('--template', '-t', help="Path to template file",
                    default=os.path.join(os.path.dirname(sys.argv[0]), 'config.ini.tmpl'),
                    )
args = parser.parse_args()

missing = []
for req in REQUIRED:
    if req not in env:
        missing.append(req)

if missing:
    print "Missing environment: " + ",".join(missing)
    sys.exit(1)

cfg = ConfigParser.ConfigParser()
cfg.read([args.template])

cfg.set('api', 'host', envget('API_HOST'))
cfg.set('api', 'port', envget('API_PORT'))
cfg.set('api', 'https', envget('API_HTTPS'))

cfg.set('amqp', 'host', envget('AMQP_HOST') or envget('API_HOST'))
if not cfg.get('amqp', 'host'):
    print "AMQP host not specified"
    sys.exit(2)

cfg.set('amqp', 'userid', env['AMQP_USER'])
cfg.set('amqp', 'passwd', env['AMQP_PASSWD'])

cfg.set('public', 'uuid', env['PROBE_UUID'])
cfg.set('public', 'secret', env['PROBE_SECRET'])

if 'PROBE_QUEUE' in env:
    cfg.set('public', 'queue', env['PROBE_QUEUE'])
if 'PROBE_NETWORK' in env:
    cfg.set('public', 'network', env['PROBE_NETWORK'])
if 'PROBE_SELFTEST' in env:
    cfg.set('public', 'selftest', env['PROBE_SELFTEST'])

with open(args.output, 'w') as fp:
    cfg.write(fp)
