import pytest
import sys
import os
myPath = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, myPath + '/../src')
sys.path.insert(0, myPath + '/../src/profinet_dcp')
sys.path.insert(0, myPath + '/../tests')
import cw_dcp


class TestDCPIdentify:

    def test_identify_all_devices(self, instance_dcp):
        devices = instance_dcp.identify_all()
        assert devices
        for device in devices:
            assert device.NameOfStation
            assert device.MAC
            assert device.IP
            assert device.Netmask
            assert device.Gateway

    def test_identify_device(self, instance_dcp):
        devices = instance_dcp.identify_all()
        assert devices
        for device in devices:
            identified = instance_dcp.identify(device.MAC)
            assert isinstance(identified, cw_dcp.Device)




