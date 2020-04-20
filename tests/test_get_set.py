import pytest
import sys
sys.path.insert(0, '../src')
sys.path.insert(0, '../src/profinet_dcp')
sys.path.insert(0, '../tests')
import cw_dcp
import configparser
import time


class TestDCPGetSet:
    config = configparser.ConfigParser()
    config.read('testconfig.ini')
    iface = config.get('BasicConfigurations', 'interface')
    mac = config.get('BasicConfigurations', 'mac')
    dcp = cw_dcp.CodewerkDCP(iface, mac)
    devices = dcp.identify_all()

    def test_get_ip(self):
        assert self.devices
        for device in self.devices:
            ip = self.dcp.get_ip_address(device.MAC)
            assert ip
            print(ip)

    def test_get_name(self):
        assert self.devices
        name = self.dcp.get_name_of_station('08:00:06:02:01:27')
        assert name
        print(name)
        # for device in self.devices:
        #     name = self.dcp.get_name_of_station(device.MAC)
        #     assert name
        #     print(name)

    def test_set_ip(self):
        assert self.devices
        for device in self.devices:
            valid_ip = self.dcp.get_ip_address(device.MAC)
            self.dcp.set_ip_address(device.MAC, '10.0.1.36')
            ip_tmp = self.dcp.get_ip_address(device.MAC)
            assert ip_tmp != valid_ip
            print('{} != {}')
            self.dcp.set_ip_address(device.MAC, valid_ip)
            ip = self.dcp.get_ip_address(device.MAC)
            assert ip == valid_ip
            print('{} == {}')
            print()

    # Works only for 08:00:06:02:01:27
    def test_set_name(self):
        assert self.devices
        dst_mac = '08:00:06:02:01:27'
        # self.dcp.set_name_of_station(dst_mac, 'new-name')
        # for device in self.devices:
        valid_name = self.dcp.get_name_of_station(dst_mac)
        self.dcp.set_name_of_station(dst_mac, 'new-name')
        name_tmp = self.dcp.get_name_of_station(dst_mac)
        assert name_tmp != valid_name
        print('{} != {}'.format(name_tmp, valid_name))
        self.dcp.set_name_of_station(dst_mac, valid_name)
        name = self.dcp.get_name_of_station(dst_mac)
        assert name == valid_name
        print('{} == {}'.format(name, valid_name))
        print()
