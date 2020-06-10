import pytest
from mock_return import MockReturn


class TestDCPGetSet:
    mock = MockReturn()

    def test_get_ip(self, instance_dcp):
        instance_dcp, socket = instance_dcp
        for device_mac in self.mock.dst:

            self.mock.dst_custom = device_mac
            socket().recv.return_value = self.mock.identify_response('GET_IP')
            socket().recv.return_value.append(TimeoutError)
            socket().recv.side_effect = socket().recv.return_value

            ip = instance_dcp.get_ip_address(device_mac)
            assert ip
            print(device_mac, ' ', ip)

    def test_get_name(self, instance_dcp):
        instance_dcp, socket = instance_dcp
        for device_mac in self.mock.dst:

            self.mock.dst_custom = device_mac
            socket().recv.return_value = self.mock.identify_response('GET_NAME')
            socket().recv.return_value.append(TimeoutError)
            socket().recv.side_effect = socket().recv.return_value

            name = instance_dcp.get_name_of_station(device_mac)
            assert name
            print(device_mac, ' ', name)

    def test_set_ip(self, instance_dcp):
        instance_dcp, socket = instance_dcp
        new_ip = ['10.0.0.31', '255.255.240.0', '10.0.0.1']
        for device_mac in self.mock.dst:

            self.mock.dst_custom = device_mac
            socket().recv.return_value = self.mock.identify_response('SET')
            socket().recv.return_value.append(TimeoutError)
            socket().recv.side_effect = socket().recv.return_value

            ret_msg = instance_dcp.set_ip_address(device_mac, new_ip)
            assert ret_msg
            print('{} -- {}'.format(device_mac, ret_msg))

    def test_set_name(self, instance_dcp):
        instance_dcp, socket = instance_dcp
        for idx in range(len(self.mock.dst)):

            self.mock.dst_custom = self.mock.dst[idx]
            socket().recv.return_value = self.mock.identify_response('SET')
            socket().recv.return_value.append(TimeoutError)
            socket().recv.side_effect = socket().recv.return_value

            new_name = 'name-{}'.format(idx)
            ret_msg = instance_dcp.set_name_of_station(self.mock.dst[idx], new_name)
            assert ret_msg
            print('{} -- {}'.format(self.mock.dst[idx], ret_msg))
