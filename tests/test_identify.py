import pytest
import sys
sys.path.insert(0, '../src')
sys.path.insert(0, '../src/profinet_dcp')
sys.path.insert(0, '../tests')
import cw_dcp
import configparser

config = configparser.ConfigParser()
config.read('testconfig.ini')
iface = config.get('BasicConfigurations', 'interface')
devices = []


def test_identify_all_devices():
    assert iface
    dcp = cw_dcp.CodewerkDCP(iface)
    devices = dcp.identify_all()
    assert devices


@pytest.mark.skipif(len(devices) == 0, reason='No devices identified in the interface {}'.format(iface))
@pytest.mark.parametrize('index', range(len(devices)))
def test_identify_device(index):
    dcp = cw_dcp.CodewerkDCP(iface)
    dcp.rec_mac = devices[index].MAC
    dcp.identify()
    dcp.read_response()
    assert iface



