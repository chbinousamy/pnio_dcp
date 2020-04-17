import pytest
import sys
sys.path.insert(0, '../src')
sys.path.insert(0, '../src/profinet_dcp')
sys.path.insert(0, '../tests')
import cw_dcp
import configparser


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
        for device in self.devices:
            name = self.dcp.get_name_of_station(device.MAC)
            assert name
            print(name)

    def test_set_ip(self):
        assert self.devices
        for device in self.devices:
            valid_ip = self.dcp.get_param(device.MAC, 'ip')
            self.dcp.set_ip_address(device.MAC, '10.0.1.36')
            device_tmp = self.dcp.identify(device.MAC)
            assert device_tmp.IP != valid_ip
            self.dcp.set_ip_address(device.MAC, valid_ip)
            device_tmp = self.dcp.identify(device.MAC)
            assert device_tmp.IP == valid_ip

    def test_set_name(self):
        assert self.devices
        for device in self.devices:
            valid_name = self.dcp.get_param(device.MAC, 'name')
            self.dcp.set_name_of_station(device.MAC, 'some-name')
            device_tmp = self.dcp.identify(device.MAC)
            assert device_tmp.NameOfStation != valid_name
            self.dcp.set_name_of_station(device.MAC, valid_name)
            device_tmp = self.dcp.identify(device.MAC)
            assert device_tmp.NameOfStation == valid_name
