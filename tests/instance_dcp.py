import pytest
import pnio_dcp
import configparser
from unittest.mock import patch, MagicMock
from mock_return import MockReturn


@pytest.fixture(scope='function')
@patch('scapy.all.conf.L2socket')
@patch('pnio_dcp.pnio_dcp.psutil')
def instance_dcp(psutil, socket):

    mock_return = MockReturn()

    psutil.net_if_addrs.return_value = mock_return.testnetz

    config = configparser.ConfigParser()
    config.read('testconfig.ini')
    ip = config.get('BasicConfigurations', 'ip')
    assert ip, 'IP-Address is not set'
    dcp = pnio_dcp.DCP(ip)
    dcp._DCP__reopen_socket = MagicMock()
    return dcp, socket
