import pytest
import sys
import os
myPath = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, myPath + '/../src')
sys.path.insert(0, myPath + '/../src/profinet_dcp')
sys.path.insert(0, myPath + '/../tests')
import cw_dcp
import configparser


class TestDCPIdentify:
    config = configparser.ConfigParser()
    config.read('testconfig.ini')
    iface = config.get('BasicConfigurations', 'interface')
    mac = config.get('BasicConfigurations', 'mac')
    ip = config.get('BasicConfigurations', 'ip')
    devices = []

    def test_identify_all_devices(self):
        assert self.iface, 'Network interface is not set'
        assert self.mac, 'MAC-Address is not set'
        # assert self.ip, 'IP-Address is not set'
        dcp = cw_dcp.CodewerkDCP(self.iface, self.mac)
        # dcp = cw_dcp.CodewerkDCP(self.ip)
        devices = dcp.identify_all()
        assert devices, 'No devices identified'
        for device in devices:
            print(device.MAC)

    # @pytest.mark.skipif(len(devices) == 0, reason='No devices identified in the interface {}'.format(iface))
    # @pytest.mark.parametrize('index', range(len(devices)))
    def test_identify_device(self):
        assert self.iface, 'Network interface is not set'
        dcp = cw_dcp.CodewerkDCP(self.iface, self.mac)
        devices = dcp.identify_all()
        for device in devices:
            identified = dcp.identify(device.MAC)
            assert isinstance(identified, cw_dcp.Device)




