import pytest
import os, sys
myPath = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, myPath + '/../../cw_dcp')
sys.path.insert(0, myPath + '/../')
import cw_dcp
import configparser
from unittest.mock import patch
from mock_return import MockReturn


@pytest.fixture(scope='function')
@patch('cw_dcp.scapy.all.conf.L2socket')
@patch('cw_dcp.psutil')
def instance_dcp(psutil, socket):

    mock_return = MockReturn()

    psutil.net_if_addrs.return_value = mock_return.testnetz

    config = configparser.ConfigParser()
    config.read('testconfig.ini')
    ip = config.get('BasicConfigurations', 'ip')
    assert ip, 'IP-Address is not set'
    dcp = cw_dcp.CodewerkDCP(ip)
    return dcp, socket

