import pytest
from mock_return import MockReturn
import random


class TestInvalidInput:
    mock = MockReturn()

    def test_provide_invalid_ip(self, instance_dcp):
        instance_dcp, socket = instance_dcp
        socket().recv.return_value = self.mock.identify_response('IDENTIFY_ALL')
        socket().recv.return_value.append(TimeoutError)
        socket().recv.side_effect = socket().recv.return_value
        devices = instance_dcp.identify_all()
        invalid_ip = [['260.0.270.31', '255.255.240.0', '10.0.0.1'],
                      ['10.0.0.30', '255..240.0', '10.0.0.1'],
                      ['10.0.0.30', '255.255.240.0', '10.0.1'],
                      ['10.0.0.30', '255.255.240.0', '-10.0.0.1']]
        assert devices
        test_device = random.choice(devices)

        self.mock.dst_custom = test_device.MAC
        socket().recv.return_value = self.mock.identify_response('SET')
        socket().recv.return_value.append(TimeoutError)
        socket().recv.side_effect = socket().recv.return_value
        for ip_conf in invalid_ip:
            exception_occured = False
            try:
                ret_msg = instance_dcp.set_ip_address(test_device.MAC, ip_conf)
            except BaseException:
                exception_occured = True
            assert exception_occured

    def test_provide_invalid_name(self, instance_dcp):
        instance_dcp, socket = instance_dcp
        socket().recv.return_value = self.mock.identify_response('IDENTIFY_ALL')
        socket().recv.return_value.append(TimeoutError)
        socket().recv.side_effect = socket().recv.return_value
        devices = instance_dcp.identify_all()
        assert devices
        test_device = random.choice(devices)

        self.mock.dst_custom = test_device.MAC
        socket().recv.return_value = self.mock.identify_response('SET')
        socket().recv.return_value.append(TimeoutError)
        socket().recv.side_effect = socket().recv.return_value

        names = ['name xx', 'na&/$%&me', '1name', 'name*:><', '.name']
        exception_occured = False
        for invalid_name in names:
            try:
                ret_msg = instance_dcp.set_name_of_station(test_device.MAC, invalid_name)
            except BaseException:
                exception_occured = True
            assert exception_occured
