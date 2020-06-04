import pytest
import sys
import os
myPath = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, myPath + '/../tests')
import cw_dcp
from mock_return import MockReturn


class TestDCPIdentify:
    mock = MockReturn()

    def test_identify_all_devices(self, instance_dcp):
        instance_dcp, socket = instance_dcp
        socket().recv.return_value = self.mock.identify_response('IDENTIFY_ALL')
        socket().recv.return_value.append(TimeoutError)
        socket().recv.side_effect = socket().recv.return_value

        devices = instance_dcp.identify_all()
        assert devices
        for device in devices:
            assert device.NameOfStation
            assert device.MAC
            assert device.IP
            assert device.Netmask
            assert device.Gateway

    def test_identify_device(self, instance_dcp):
        instance_dcp, socket = instance_dcp
        socket().recv.return_value = self.mock.identify_response('IDENTIFY_ALL')
        socket().recv.return_value.append(TimeoutError)
        socket().recv.side_effect = socket().recv.return_value

        devices = instance_dcp.identify_all()
        assert devices
        for device in devices:

            self.mock.dst_custom = device.MAC
            socket().recv.return_value = self.mock.identify_response('IDENTIFY')
            socket().recv.return_value.append(TimeoutError)
            socket().recv.side_effect = socket().recv.return_value

            identified = instance_dcp.identify(device.MAC)
            assert isinstance(identified, cw_dcp.Device)




