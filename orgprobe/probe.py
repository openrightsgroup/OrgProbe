import time
import logging
import random
import datetime

logger = logging.getLogger("probe")

JITTER_THRESHOLD = 30

class SelfTestError(Exception):
    pass


class Probe(object):
    def __init__(self,
                 url_tester,
                 queue,
                 isp,
                 ip,
                 probe_config,
                 apiconfig):
        self.url_tester = url_tester
        self.queue = queue
        self.isp = isp
        self.ip = ip
        self.probe_config = probe_config
        self.apiconfig = apiconfig

    def run_test(self, data):
        logger.debug("run_test %s", data)

        action = data.get('action', 'run_test')
        if 'url' in data:
            self._test_and_report_url(data['url'], data['hash'], data.get('request_id'))
        elif 'urls' in data:
            for url in data['urls']:
                self._test_and_report_url(url['url'], data['hash'], request_id=data.get('request_id'))

    def run_startup_selftest(self, override=False):
        logger.debug("run_startup_selftest")

        if self.probe_config.get('selftest', 'true').lower() != 'true' and not override:
            logger.debug("selftest on startup disabled")
            return

        allow_partial = self.probe_config.get('partial_selftest', 'false') == 'true'

        partial_results = []
        # run the selftest anyway of override == True
        for url in self.apiconfig['self-test']['must-allow']:
            if self.url_tester.test_url(url).status != 'ok':
                if not allow_partial:
                    raise SelfTestError
                partial_results.append(False)
            else:
                partial_results.append(True)
        if not any(partial_results):
            raise SelfTestError

        partial_results = []
        for url in self.apiconfig['self-test']['must-block']:
            if self.url_tester.test_url(url).status != 'blocked':
                if not allow_partial:
                    raise SelfTestError
                partial_results.append(False)
            else:
                partial_results.append(True)
        if not any(partial_results):
            raise SelfTestError

    @classmethod
    def _get_timestamp(cls):
        return datetime.datetime.utcnow()

    @classmethod
    def _jitter_delay(cls, data):
        if data.get('jitter', False) and 'submitted' in data:
            submit_time = datetime.datetime.strptime(data['submitted'], '%Y-%m-%dT%H:%M:%S')
            if submit_time > cls._get_timestamp() - datetime.timedelta(0, JITTER_THRESHOLD):
                time.sleep(random.randint(5, 45))

    def _test_and_report_url(self, url, urlhash=None, request_id=None):
        logger.debug("test_and_report_url %s, %s, %s", url, urlhash, request_id)
        result = self.url_tester.test_url(url)

        logger.debug("Result: %s; %s", request_id, result)
        report = self._build_report(request_id, result, url)

        self.queue.send_report(report, urlhash)

    def _build_report(self, request_id, result, url):
        report = {
            'network_name': self.isp,
            'ip_network': self.ip,
            'url': url,
            'http_status': result.code,
            'status': result.status,
            'probe_uuid': self.probe_config['uuid'],
            'config': self.apiconfig['version'],
            'category': result.category or '',
            'blocktype': result.type or '',
            'title': result.title or '',
            'remote_ip': result.ip or '',
            'ssl_verified': None,
            'ssl_fingerprint': result.ssl_fingerprint,
            'request_id': request_id,
            'final_url': result.final_url,
            'resolved_ip': result.resolved_ip
        }
        if self.probe_config.get('verify_ssl', '').lower() == 'true':
            report.update({
                'ssl_verified': result.ssl_verified,
            })
        if self.probe_config.get('record_requests', '').lower() == 'true':
            report['request_data'] = result.request_data
        return report

    def _run_selftest(self, request_id):
        logger.debug("run_selftest")

        detailed_results = {
            "must-allow": [(url, self.url_tester.test_url(url))
                           for url in self.apiconfig['self-test']['must-allow']],
            "must-block": [(url, self.url_tester.test_url(url))
                           for url in self.apiconfig['self-test']['must-block']]
        }

        if any(result[1].status != 'ok' for result in detailed_results["must-allow"]):
            logger.error("Self-test failed - couldn't access some sites in 'must-allow' list")
            result = "error"
        elif any(result[1].status != 'blocked' for result in detailed_results["must-block"]):
            logger.info("Self-test showed filter disabled")
            result = "filter_disabled"
        else:
            logger.info("Self-test showed filter enabled")
            result = "filter_enabled"

