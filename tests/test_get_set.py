import pytest
import sys
import os
myPath = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, myPath + '/../src')
sys.path.insert(0, myPath + '/../src/profinet_dcp')
sys.path.insert(0, myPath + '/../tests')


class TestDCPGetSet:

    def test_get_ip(self, instance_dcp):
        devices = instance_dcp.identify_all()
        assert devices
        for device in devices:
            ip = instance_dcp.get_ip_address(device.MAC)
            assert ip

    def test_get_name(self, instance_dcp):
        devices = instance_dcp.identify_all()
        assert devices
        for device in devices:
            name = instance_dcp.get_name_of_station(device.MAC)
            assert name
            print(device.MAC, ' ', name)

    def test_set_ip(self, instance_dcp):
        devices = instance_dcp.identify_all()
        new_ip = ['10.0.0.31', '255.255.240.0', '10.0.0.1']
        assert devices
        for idx in range(len(devices)):
            valid_ip = instance_dcp.get_ip_address(devices[idx].MAC)
            err_msg = instance_dcp.set_ip_address(devices[idx].MAC, new_ip)
            if new_ip[0] == valid_ip:
                continue
            ip_tmp = instance_dcp.get_ip_address(devices[idx].MAC)
            if err_msg is None:
                assert ip_tmp != valid_ip
                instance_dcp.set_ip_address(devices[idx].MAC, [valid_ip, '255.255.240.0', '10.0.0.1'])
                ip = instance_dcp.get_ip_address(devices[idx].MAC)
                assert ip == valid_ip
            else:
                print('{} -- {}'.format(devices[idx].MAC, err_msg))

    def test_set_name(self, instance_dcp):
        devices = instance_dcp.identify_all()
        assert devices
        for idx in range(len(devices)):
            new_name = 'name-{}'.format(idx)
            valid_name = instance_dcp.get_name_of_station(devices[idx].MAC)
            err_msg = instance_dcp.set_name_of_station(devices[idx].MAC, new_name)
            if new_name == valid_name:
                continue
            name_tmp = instance_dcp.get_name_of_station(devices[idx].MAC)
            if err_msg is None:
                assert name_tmp != valid_name
                instance_dcp.set_name_of_station(devices[idx].MAC, valid_name)
                name = instance_dcp.get_name_of_station(devices[idx].MAC)
                assert name == valid_name
            else:
                print('{} -- {}'.format(devices[idx].MAC, err_msg))
