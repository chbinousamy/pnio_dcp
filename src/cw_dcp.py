import sys
import os
myPath = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, myPath + '/../src')
from scapy.all import *
from profinet_dcp.util import *
from profinet_dcp.protocol import *
import psutil
from unittest.mock import Mock
from mock_return import MockReturn


class Device:

    NameOfStation = ''
    MAC = ''
    IP = ''
    Netmask = ''
    Gateway = ''


class CodewerkDCP:
    def __init__(self, ip):
        self.if_mock = False
        self.devices = []
        self.dst_mac = ''
        self.src_mac, self.iface = self.__get_nic(ip)
        self.s = conf.L2socket(iface=self.iface)
        self.mock = MockReturn()
        self.frame = None
        self.service = None
        self.service_type = None

    def __define_mock_interface(self, request):
        self.s = Mock()
        self.s.recv.return_value = self.mock.identify_response(request)
        self.s.recv.return_value.append(TimeoutError)
        self.s.recv.side_effect = self.s.recv.return_value

    def __get_nic(self, ip):
        '''
        Identify network interface name and MAC-address using IP-address
        :param ip: IP-address (str)
        :return: MAC-address (str), Interface name (str)
        '''
        addrs = psutil.net_if_addrs()
        for iface_name, config in addrs.items():
            iface_mac = config[0][1]
            iface_ip = config[1][1]
            if iface_ip == ip:
                return iface_mac.replace('-', ':').lower(), iface_name

    def ip_to_hex(self, ip_conf):
        '''
        Converts list containing strings with IP-address, subnet mask and router into byte-string.
        :param ip_conf: list of strings in order ['ip address', 'subnet mask', 'router']
        :return: string of bytes, the content of ip_conf has been converted to hex and joint together.
        '''
        str_hex = ''
        for param in ip_conf:
            nums = list(param.split('.'))
            for i in nums:
                str_hex += hex(int(i))[2:].zfill(2)
        return bytes.fromhex(str_hex)

    def identify_all(self):
        '''
        Send multicast request to identify ALL devices in current network interface
        and get information (name, ip) about them.
        :return: list with instances of class Device, an instance is created for each device found.
        '''
        self.dst_mac = '01:0e:cf:00:00:00'
        self.frame, self.service, self.service_type = 0xfefe, PNDCPHeader.IDENTIFY, PNDCPHeader.REQUEST
        self.__send_request(0xFF, 0xFF, 0)
        return self.read_response(debug=False)

    def identify(self, mac):
        '''
        Get information (name, IP) about specific device in the network interface
        :param mac: MAC-address of the device to identify
        :return: instance of class Device
        '''
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefe, PNDCPHeader.IDENTIFY, PNDCPHeader.REQUEST
        self.__send_request(0xFF, 0xFF, 0)
        return self.read_response()[0]

    def set_ip_address(self, mac, ip_conf):
        '''
        Set or change IP configurations of a specific device
        :param mac: MAC-address of target device
        :param ip_conf: list of strings in order ['ip address', 'subnet mask', 'router']
        :return: error message, None if no error occurred, str otherwise
        '''
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefd, PNDCPHeader.SET, PNDCPHeader.REQUEST
        hex_addr = self.ip_to_hex(ip_conf)
        self.__send_request(PNDCPBlock.IP_ADDRESS[0], PNDCPBlock.IP_ADDRESS[1], len(hex_addr)+2, hex_addr)
        time.sleep(2)
        return self.read_response(once=True, debug=False, get=False, set=True)

    def set_name_of_station(self, mac, name):
        '''
        Set or change the name of station of a specific device
        :param mac: MAC-address of target device
        :param name: str with the name to set
        :return: error message, None if no error occurred, str otherwise
        '''
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefd, PNDCPHeader.SET, PNDCPHeader.REQUEST
        self.__send_request(PNDCPBlock.NAME_OF_STATION[0], PNDCPBlock.NAME_OF_STATION[1], len(name)+2, bytes(name, encoding='ascii'))
        time.sleep(2)
        return self.read_response(once=True, debug=False, get=False, set=True)

    def get_ip_address(self, mac):
        '''
        Get IP-address of a specific device
        :param mac: MAC-address of target device
        :return: IP-address (str)
        '''
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefd, PNDCPHeader.GET, PNDCPHeader.REQUEST
        self.__send_request(PNDCPBlock.IP_ADDRESS[0], PNDCPBlock.IP_ADDRESS[1], 0)
        # return list(self.read_response(once=True, debug=False, get=True).values())[0]['ip']
        return self.read_response(once=True, debug=False, get=True)

    def get_name_of_station(self, mac):
        '''
        Get name of station of a specific device
        :param mac: MAC-address of target device
        :return: name of station (decoded str)
        '''
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefd, PNDCPHeader.GET, PNDCPHeader.REQUEST
        self.__send_request(PNDCPBlock.NAME_OF_STATION[0], PNDCPBlock.NAME_OF_STATION[1], 0)
        # return list(self.read_response(once=True, debug=False, get=True).values())[0]['name'].decode()
        return self.read_response(once=True, debug=False, get=True).decode()

    def __send_request(self, opt, subopt, length, value=None):
        '''
        Send DCP-package
        :param opt: Option of DCP data block in range 1 to 5
        :param subopt: Suboption of DCP data block
        :param length: length of DCP payload data, 0 if no data to send
        :param value: data to send, only used in 'set' functions
        '''
        if not value:
            block_content = bytes()
        else:
            block_content = bytes([0x00, 0x01]) + value
            block_length = len(value) + 6 + (1 if len(value) % 2 == 1 else 0)
        block = PNDCPBlockRequest(opt, subopt, length, block_content)
        dcp = PNDCPHeader(self.frame, self.service, self.service_type, 0x7010052, 0x0080, block_length if value else len(block), payload=block)
        eth = EthernetVLANHeader(s2mac(self.dst_mac), s2mac(self.src_mac), 0x8892, payload=dcp)
        if self.if_mock:
            self.__define_mock_interface(bytes(eth))
        self.s.send(bytes(eth))

    def __response_set(self, payload):
        '''
        Analyze DCP payload to identify if communication was successfull, return error message otherwise.
        :param payload: byte string with DCP payload
        :return: error message, None if no error occurred, str otherwise
        '''
        error_codes = {1: 'Option unsupported',
                       2: 'Suboption unsupported or no DataSet available',
                       3: 'Suboption not set',
                       4: 'Resource Error',
                       5: 'SET not possible by local reasons',
                       6: 'In operation, SET not possible'}
        block_error = payload[6]
        if block_error != 0:
            error_message = 'SET unsuccessful, BlockError with code {} ({})'.format(block_error, error_codes[block_error])
        else:
            error_message = None
        return error_message

    def read_response(self, to=10, once=False, debug=True, get=False, set=False):
        '''
        Receive packages in the network, filter DCP packages addressed to the current host and decode them
        :param to: timeout in sec
        :param once: script should run only once (only 1 package to receive, ex.: get-functions)
        :param debug: print device information in the output window
        :param get: this function was called inside a get-function, True to return only 1 parameter needed
        :param set: this function was called inside a set-function, True enables error detection
        :return: string parameter if 'get', DCP payload if 'set', list with instances of class Device otherwise.
        '''
        ret = {}
        found = []
        try:
            with max_timeout(to) as t:
                while True:
                    if t.timed_out:
                        break
                    try:
                        data = self.s.recv()
                        if data is None:
                            continue
                        data = bytes(data)
                    except timeout:
                        continue

                    eth = EthernetHeader(data)
                    if mac2s(eth.dst) != self.src_mac or eth.type != PNDCPHeader.ETHER_TYPE:
                        continue
                    debug and print("MAC address:", mac2s(eth.src))

                    pro = PNDCPHeader(eth.payload)
                    if not (pro.service_type == PNDCPHeader.RESPONSE):
                        continue

                    blocks = pro.payload
                    if set and blocks[0] == 5:
                        msg = self.__response_set(blocks)
                        return msg
                    length = pro.length
                    parsed = {}

                    device = Device()
                    device.MAC = mac2s(eth.src)

                    while length > 6:
                        block = PNDCPBlock(blocks)
                        blockoption = (block.option, block.suboption)
                        parsed[blockoption] = block.payload

                        block_len = block.length
                        if blockoption == PNDCPBlock.NAME_OF_STATION:
                            debug and print("Name of Station: %s" % block.payload)
                            parsed["name"] = block.payload
                            device.NameOfStation = block.payload.decode()
                            if get:
                                return block.payload
                        elif blockoption == PNDCPBlock.IP_ADDRESS:
                            debug and print(str(block.parse_ip()))
                            parsed["ip"] = s2ip(block.payload[0:4])
                            if get:
                                return s2ip(block.payload[0:4])
                            device.IP = s2ip(block.payload[0:4])
                            device.Netmask = s2ip(block.payload[4:8])
                            device.Gateway = s2ip(block.payload[8:12])
                        elif blockoption == PNDCPBlock.DEVICE_ID:
                            parsed["devId"] = block.payload


                        if block_len % 2 == 1:
                            block_len += 1

                        blocks = blocks[block_len + 4:]
                        length -= 4 + block_len

                    ret[eth.src] = parsed
                    found.append(device)

                    if once:
                        break

        except TimeoutError:
            pass

        if get:
            return ret
        else:
            return found
