import configparser

from orgprobe.bootstrapper import setup_accounting


def test_config_no_accounting_section():
    config = configparser.ConfigParser()
    assert setup_accounting(config, {}, "ISP") is None


def test_config_no_accounting_key():
    config = configparser.ConfigParser()
    config.read_string(u"""[accounting]""")
    assert setup_accounting(config, {}, "ISP") is None


def test_config_no_accounting_value():
    config = configparser.ConfigParser()
    config.read_string(u"""[accounting]\nredis_server=""")
    assert setup_accounting(config, {}, "ISP") is None


def test_config_with_accounting(mocker):
    Accounting = mocker.patch('orgprobe.bootstrapper.Accounting')

    instance = Accounting.return_value

    config = configparser.ConfigParser()
    config.read_string(u"""[accounting]\nredis_server=foo""")

    assert setup_accounting(config, {}, "ExampleISP") is instance

    Accounting.assert_called_with(config, "exampleisp", {})
