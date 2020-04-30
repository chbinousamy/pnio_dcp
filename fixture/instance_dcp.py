import pytest
import os, sys
myPath = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, myPath + '/../src')
sys.path.insert(0, myPath + '/../tests')
import cw_dcp
import configparser


@pytest.fixture(scope='function')
def instance_dcp():
    config = configparser.ConfigParser()
    config.read('testconfig.ini')
    ip = config.get('BasicConfigurations', 'ip')
    assert ip, 'IP-Address is not set'
    dcp = cw_dcp.CodewerkDCP(ip)
    devices = dcp.identify_all()
    if len(devices) == 0:
        dcp.if_mock = True
    return dcp

