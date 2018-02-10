import logging

logger = logging.getLogger("probe")


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
        if action == "run_test":
            if 'url' in data:
                self._test_and_report_url(data['url'], data['hash'], data.get('request_id'))
            elif 'urls' in data:
                for url in data['urls']:
                    self._test_and_report_url(url['url'], data['hash'], request_id=data.get('request_id'))
        elif action == "run_selftest":
            self._run_selftest(data['request_id'])
        else:
            logger.warn("Dropping message with unknown action: %s", action)

    def run_startup_selftest(self):
        logger.debug("run_startup_selftest")

        if self.probe_config.get('selftest', 'true').lower() != 'true':
            logger.debug("selftest on startup disabled")
        else:
            for url in self.apiconfig['self-test']['must-allow']:
                if self.url_tester.test_url(url).status != 'ok':
                    raise SelfTestError
            for url in self.apiconfig['self-test']['must-block']:
                if self.url_tester.test_url(url).status != 'blocked':
                    raise SelfTestError

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
            'final_url': result.final_url
        }
        if self.probe_config.get('verify_ssl', '').lower() == 'true':
            report.update({
                'ssl_verified': result.ssl_verified,
            })
        return report

    def _run_selftest(self, request_id):
        logger.debug("run_selftest")

        results = {
            "must-allow": [(url, self.url_tester.test_url(url))
                           for url in self.apiconfig['self-test']['must-allow']],
            "must-block": [(url, self.url_tester.test_url(url))
                           for url in self.apiconfig['self-test']['must-block']]
        }
        is_failed_selftest = (any(result[1].status != 'ok' for result in results["must-allow"]) or
                              any(result[1].status != 'blocked' for result in results["must-block"]))

        if is_failed_selftest:
            logger.warn("Failed self-test %s", results)
        else:
            logger.info("Self-test successful")

        self.queue.send_selftest_report(
            self._build_selftest_report(request_id, is_failed_selftest, results))

    def _build_selftest_report(self, request_id, is_failed_selftest, results):
        must_allow = [self._build_report(request_id, result, url)
                      for url, result in results["must-allow"]]
        must_block = [self._build_report(request_id, result, url)
                      for url, result in results["must-block"]]
        return {
            "request_id": request_id,
            "is_failed_selftest": is_failed_selftest,
            "probe_uuid": self.probe_config['uuid'],
            "details": {
                "must-allow": must_allow,
                "must-block": must_block
            }
        }
