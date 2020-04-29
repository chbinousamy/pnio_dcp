import pytest
import sys
import os
myPath = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, myPath + '/../src')
sys.path.insert(0, myPath + '/../src/profinet_dcp')
sys.path.insert(0, myPath + '/../tests')
# import cw_dcp
import cw_dcp_mock as cw_dcp
import configparser


class TestDCPGetSet:
    config = configparser.ConfigParser()
    config.read('testconfig.ini')
    ip = config.get('BasicConfigurations', 'ip')
    dcp = cw_dcp.CodewerkDCP(ip)
    devices = dcp.identify_all()

    def test_get_ip(self):
        assert self.devices
        print()
        for device in self.devices:
            ip = self.dcp.get_ip_address(device.MAC)
            assert ip
            print(device.MAC, ' ', ip)

    def test_get_name(self):
        assert self.devices
        print()
        for device in self.devices:
            name = self.dcp.get_name_of_station(device.MAC)
            assert name
            print(device.MAC, ' ', name)

    def test_set_ip(self):
        assert self.devices
        for idx in range(len(self.devices)):
            valid_ip = self.dcp.get_ip_address(self.devices[idx].MAC)
            err_msg = self.dcp.set_ip_address(self.devices[idx].MAC, ['10.0.0.31', '255.255.240.0', '10.0.0.1'])
            ip_tmp = self.dcp.get_ip_address(self.devices[idx].MAC)
            if err_msg is None:
                assert ip_tmp != valid_ip
                self.dcp.set_ip_address(self.devices[idx].MAC, [valid_ip, '255.255.240.0', '10.0.0.1'])
                ip = self.dcp.get_ip_address(self.devices[idx].MAC)
                assert ip == valid_ip
            else:
                print('{} -- {}'.format(self.devices[idx].MAC, err_msg))

    def test_set_name(self):
        assert self.devices
        print()
        for idx in range(len(self.devices)):
            msg = self.dcp.set_name_of_station(self.devices[idx].MAC, 'name-{}'.format(idx))
            print('{} -- {}'.format(self.devices[idx].MAC, msg))
