import pytest
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
            assert device.name_of_station
            assert device.MAC
            assert device.IP
            assert device.netmask
            assert device.gateway

    def test_identify_device(self, instance_dcp):
        instance_dcp, socket = instance_dcp
        for device_mac in self.mock.dst:
            self.mock.dst_custom = device_mac
            socket().recv.return_value = self.mock.identify_response('IDENTIFY')
            socket().recv.return_value.append(TimeoutError)
            socket().recv.side_effect = socket().recv.return_value

            identified = instance_dcp.identify(device_mac)
            assert isinstance(identified, cw_dcp.Device)




