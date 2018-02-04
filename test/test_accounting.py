import logging
import configparser

import pytest
from OrgProbe.probe import Probe, logger
from OrgProbe.match import RulesMatcher

logger.setLevel(logging.FATAL)


@pytest.fixture
def probe():
    probe = Probe({})
    probe.probe = {}
    probe.rules_matcher = RulesMatcher([], [], [])
    return probe


def test_config_no_accounting_section(probe):
    probe.config = configparser.ConfigParser()
    probe.setup_accounting()
    assert probe.counters is None


def test_config_no_accounting_key(probe):
    probe.config = configparser.ConfigParser()
    probe.config.read_string(u"""[accounting]""")
    probe.setup_accounting()
    assert probe.counters is None


def test_config_no_accounting_value(probe):
    probe.config = configparser.ConfigParser()
    probe.config.read_string(u"""[accounting]\nredis_server=""")
    probe.setup_accounting()
    assert probe.counters is None


def test_config_with_accounting(probe, mocker):
    Accounting = mocker.patch('OrgProbe.probe.Accounting')

    instance = Accounting.return_value

    probe.config = configparser.ConfigParser()
    probe.config.read_string(u"""[accounting]\nredis_server=foo""")
    probe.isp = "ExampleISP"

    probe.setup_accounting()

    Accounting.assert_called_with(probe.config, "exampleisp", probe.probe)
    assert probe.counters is instance
