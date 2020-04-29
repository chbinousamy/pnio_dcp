import pytest
import sys
import os
myPath = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, myPath + '/../src')
sys.path.insert(0, myPath + '/../src/profinet_dcp')
sys.path.insert(0, myPath + '/../tests')
# import cw_dcp
import cw_dcp_mock as cw_dcp
import configparser
import binascii
from unittest.mock import Mock, patch, MagicMock


class TestDCPIdentify:
    config = configparser.ConfigParser()
    config.read('testconfig.ini')
    ip = config.get('BasicConfigurations', 'ip')
    devices = []

    def test_identify_all_devices(self):
        assert self.ip, 'IP-Address is not set'
        dcp = cw_dcp.CodewerkDCP(self.ip)
        devices = dcp.identify_all()
        for device in devices:
            print(device.MAC)

    def test_identify_device(self):
        assert self.ip, 'IP-address is not set'
        dcp = cw_dcp.CodewerkDCP(self.ip)
        devices = dcp.identify_all()
        assert devices
        for device in devices:
            identified = dcp.identify(device.MAC)
            assert isinstance(identified, cw_dcp.Device)




