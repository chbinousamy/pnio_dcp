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
        macs_identified = []
        assert devices
        for device in devices:
            macs_identified.append(device.MAC)

            assert device.name_of_station == self.mock.devices[device.MAC].NameOfStation
            assert device.MAC == self.mock.devices[device.MAC].MAC
            assert device.IP == self.mock.devices[device.MAC].IP
            assert device.netmask == self.mock.devices[device.MAC].Netmask
            assert device.gateway == self.mock.devices[device.MAC].Gateway
            assert device.family == self.mock.devices[device.MAC].Family

        assert macs_identified == self.mock.dst

    def test_identify_device(self, instance_dcp):
        instance_dcp, socket = instance_dcp
        for device_mac in self.mock.dst:
            self.mock.dst_custom = device_mac
            socket().recv.return_value = self.mock.identify_response('IDENTIFY')
            socket().recv.return_value.append(TimeoutError)
            socket().recv.side_effect = socket().recv.return_value

            identified = instance_dcp.identify(device_mac)
            assert isinstance(identified, cw_dcp.Device)
            assert identified.name_of_station == self.mock.devices[device_mac].NameOfStation
            assert identified.MAC == self.mock.devices[device_mac].MAC
            assert identified.IP == self.mock.devices[device_mac].IP
            assert identified.netmask == self.mock.devices[device_mac].Netmask
            assert identified.gateway == self.mock.devices[device_mac].Gateway
            assert identified.family == self.mock.devices[device_mac].Family





