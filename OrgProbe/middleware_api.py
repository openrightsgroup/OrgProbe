import logging
import requests


class MiddlewareAPI(object):
    def __init__(self, config, signer):
        self.signer = signer

        if config.has_option('api', 'url'):
            self.url_base = config.get('api', 'url')
        else:
            # backwards compatibility with old config keys
            https = config.getboolean('api', 'https', fallback=True)
            host = config.get('api', 'host')
            port = config.getint('api', 'port', fallback=443)
            version = config.get('api', 'version', fallback='1.2')

            self.url_base = "{}://{}:{}/{}".format(
                'https' if https else 'http',
                host,
                port,
                version)

    def status_ip(self, public_ip, probe_uuid):
        url = 'status/ip'
        if public_ip:
            url = '{}/{}'.format(url, public_ip)

        return self._execute(url,
                             args={"probe_uuid": probe_uuid},
                             send_timestamp=True,
                             sig_keys=['date'])

    def config(self, version):
        return self._execute('config/{}'.format(version))

    def _execute(self,
                 path,
                 args=None,
                 send_timestamp=False,
                 sig_keys=None):

        if not args:
            args = {}

        if send_timestamp:
            args['date'] = self.signer.timestamp()
        if sig_keys:
            args['signature'] = self.signer.get_signature(args, sig_keys)

        url = "{}/{}".format(self.url_base, path)

        logging.debug("Opening ORG Api connection to: %s with args: %s", url, args)
        response = requests.get(url, params=args)
        logging.debug("ORG Api Request Complete: %s", response.status_code)
        response.raise_for_status()

        try:
            return response.json()
        except ValueError:
            logging.error("Middleware response contained invalid JSON: %s", response.content)
            raise
