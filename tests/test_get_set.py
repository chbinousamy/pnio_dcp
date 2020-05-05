import pytest
import sys
import os
myPath = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, myPath + '/../src')
sys.path.insert(0, myPath + '/../src/profinet_dcp')
sys.path.insert(0, myPath + '/../tests')
from mock_return import MockReturn


class TestDCPGetSet:
    mock = MockReturn()

    def test_get_ip(self, instance_dcp):
        instance_dcp, socket = instance_dcp
        socket().recv.return_value = self.mock.identify_response('IDENTIFY_ALL')
        socket().recv.return_value.append(TimeoutError)
        socket().recv.side_effect = socket().recv.return_value
        devices = instance_dcp.identify_all()
        assert devices
        for device in devices:

            self.mock.dst_custom = device.MAC
            socket().recv.return_value = self.mock.identify_response('GET_IP')
            socket().recv.return_value.append(TimeoutError)
            socket().recv.side_effect = socket().recv.return_value

            ip = instance_dcp.get_ip_address(device.MAC)
            assert ip
            print(device.MAC, ' ', ip)

    def test_get_name(self, instance_dcp):
        instance_dcp, socket = instance_dcp
        socket().recv.return_value = self.mock.identify_response('IDENTIFY_ALL')
        socket().recv.return_value.append(TimeoutError)
        socket().recv.side_effect = socket().recv.return_value

        devices = instance_dcp.identify_all()
        assert devices
        for device in devices:

            self.mock.dst_custom = device.MAC
            socket().recv.return_value = self.mock.identify_response('GET_NAME')
            socket().recv.return_value.append(TimeoutError)
            socket().recv.side_effect = socket().recv.return_value

            name = instance_dcp.get_name_of_station(device.MAC)
            assert name
            print(device.MAC, ' ', name)

    def test_set_ip(self, instance_dcp):
        instance_dcp, socket = instance_dcp
        socket().recv.return_value = self.mock.identify_response('IDENTIFY_ALL')
        socket().recv.return_value.append(TimeoutError)
        socket().recv.side_effect = socket().recv.return_value
        devices = instance_dcp.identify_all()
        new_ip = ['10.0.0.31', '255.255.240.0', '10.0.0.1']
        assert devices
        for idx in range(len(devices)):

            self.mock.dst_custom = devices[idx].MAC
            socket().recv.return_value = self.mock.identify_response('SET_IP')
            socket().recv.return_value.append(TimeoutError)
            socket().recv.side_effect = socket().recv.return_value

            ret_msg = instance_dcp.set_ip_address(devices[idx].MAC, new_ip)
            assert ret_msg
            print('{} -- {}'.format(devices[idx].MAC, ret_msg))

    def test_set_name(self, instance_dcp):
        instance_dcp, socket = instance_dcp
        socket().recv.return_value = self.mock.identify_response('IDENTIFY_ALL')
        socket().recv.return_value.append(TimeoutError)
        socket().recv.side_effect = socket().recv.return_value
        devices = instance_dcp.identify_all()
        assert devices
        for idx in range(len(devices)):

            self.mock.dst_custom = devices[idx].MAC
            socket().recv.return_value = self.mock.identify_response('SET_NAME')
            socket().recv.return_value.append(TimeoutError)
            socket().recv.side_effect = socket().recv.return_value

            new_name = 'name-{}'.format(idx)
            ret_msg = instance_dcp.set_name_of_station(devices[idx].MAC, new_name)
            assert ret_msg
            print('{} -- {}'.format(devices[idx].MAC, ret_msg))
