import pytest
from mock_return import MockReturn
import random


class TestInvalidInput:
    mock = MockReturn()

    def test_provide_invalid_ip(self, instance_dcp):
        instance_dcp, socket = instance_dcp
        invalid_ip = [['260.0.270.31', '255.255.240.0', '10.0.0.1'],
                      ['10.0.0.30', '255..240.0', '10.0.0.1'],
                      ['10.0.0.30', '255.255.240.0', '10.0.1'],
                      ['10.0.0.30', '255.255.240.0', '-10.0.0.1']]
        test_device_mac = random.choice(self.mock.dst)
        self.mock.dst_custom = test_device_mac
        socket().recv.return_value = self.mock.identify_response('SET')
        socket().recv.return_value.append(TimeoutError)
        socket().recv.side_effect = socket().recv.return_value
        for ip_conf in invalid_ip:
            exception_occured = False
            try:
                ret_msg = instance_dcp.set_ip_address(test_device_mac, ip_conf)
            except BaseException:
                exception_occured = True
            assert exception_occured

    def test_provide_invalid_name(self, instance_dcp):
        instance_dcp, socket = instance_dcp
        test_device_mac = random.choice(self.mock.dst)

        self.mock.dst_custom = test_device_mac
        socket().recv.return_value = self.mock.identify_response('SET')
        socket().recv.return_value.append(TimeoutError)
        socket().recv.side_effect = socket().recv.return_value

        names = ['name xx', 'na&/$%&me', '1name', 'name*:><', '.name']
        exception_occured = False
        for invalid_name in names:
            try:
                ret_msg = instance_dcp.set_name_of_station(test_device_mac, invalid_name)
            except BaseException:
                exception_occured = True
            assert exception_occured
