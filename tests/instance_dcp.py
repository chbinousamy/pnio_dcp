import pytest
import cw_dcp
import configparser
from unittest.mock import patch, MagicMock
from mock_return import MockReturn


@pytest.fixture(scope='function')
@patch('scapy.all.conf.L2socket')
@patch('cw_dcp.cw_dcp.psutil')
def instance_dcp(psutil, socket):

    mock_return = MockReturn()

    psutil.net_if_addrs.return_value = mock_return.testnetz

    config = configparser.ConfigParser()
    config.read('testconfig.ini')
    ip = config.get('BasicConfigurations', 'ip')
    assert ip, 'IP-Address is not set'
    dcp = cw_dcp.CodewerkDCP(ip)
    dcp.reopen_socket = MagicMock()
    return dcp, socket
