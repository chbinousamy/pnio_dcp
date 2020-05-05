import pytest
import os, sys
myPath = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, myPath + '/../src')
sys.path.insert(0, myPath + '/../tests')
import cw_dcp
import configparser
from unittest.mock import patch
from mock_return import MockReturn


@pytest.fixture(scope='function')
@patch('cw_dcp.scapy.all.conf.L2socket')
@patch('cw_dcp.psutil')
def instance_dcp(psutil, socket):
    # sock_request = next(mark for mark in request.function.pytestmark if mark.name == 'instance_dcp').args[0]

    mock_return = MockReturn()

    psutil.net_if_addrs.return_value = mock_return.testnetz

    # socket.recv.return_value = mock_return.identify_response(sock_request)
    # socket.recv.return_value.append(TimeoutError)
    # socket.recv.side_effect = socket.recv.return_value

    config = configparser.ConfigParser()
    config.read('testconfig.ini')
    ip = config.get('BasicConfigurations', 'ip')
    assert ip, 'IP-Address is not set'
    dcp = cw_dcp.CodewerkDCP(ip)
    return dcp, socket

