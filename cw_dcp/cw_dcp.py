"""
Copyright (c) 2020 Codewerk GmbH, Karlsruhe.
All Rights Reserved.
"""
import re
import time
import logging
import psutil
from scapy.all import conf
import socket
from .protocol import dcp_header, eth_header, DCPBlock, DCPBlockRequest
from .util import mac_to_hex, hex_to_mac, hex_to_ip
from .error import DcpError, DcpTimeoutError


class Device:
    name_of_station = ''
    MAC = ''
    IP = ''
    netmask = ''
    gateway = ''
    family = ''


class CodewerkDCP:
    def __init__(self, ip):
        self.devices = []
        self.dst_mac = ''
        self.src_mac, self.iface = self.__get_nic(ip)

        # This filter in BPF format filters all unrelated packets (i.e. wrong mac address or ether type) before they are
        # processed by scapy. This solves issues in high traffic networks, as scapy is known to miss packets under heavy
        # load. See e.g. here: https://scapy.readthedocs.io/en/latest/usage.html#performance-of-scapy
        self.socket_filter = f"ether host {self.src_mac} and ether proto {dcp_header.ETHER_TYPE}"

        self.s = conf.L2socket(iface=self.iface, filter=self.socket_filter)
        self.frame = None
        self.service = None
        self.service_type = None

    def reopen_socket(self):
        self.s.close()
        self.s = conf.L2socket(iface=self.iface, filter=self.socket_filter)

    @staticmethod
    def __get_nic(ip):
        """
        Identify network interface name and MAC-address using IP-address
        :param ip: IP-address (str)
        :return: MAC-address (str), Interface name (str)
        """
        addrs = psutil.net_if_addrs()
        for iface_name, config in addrs.items():
            iface_mac = config[0][1]
            iface_ip = config[1][1]
            if iface_ip == ip:
                return iface_mac.replace('-', ':').lower(), iface_name

    @staticmethod
    def ip_to_hex(ip_conf):
        """
        Converts list containing strings with IP-address, subnet mask and router into byte-string.
        :param ip_conf: list of strings in order ['ip address', 'subnet mask', 'router']
        :return: string of bytes, the content of ip_conf has been converted to hex and joint together.
        """
        str_hex = ''
        for param in ip_conf:
            nums = list(param.split('.'))

            if len(nums) != 4:
                raise ValueError('Provided IP-address of invalid length')
            for i in nums:
                if not i.isdigit():
                    raise TypeError('Provided invalid IP-octet (non-integer): "{}"'.format(i))
                if not 0 <= int(i) <= 255:
                    raise ValueError('Provided value exceeds the allowed range of IP octets (0-255)')
                str_hex += hex(int(i))[2:].zfill(2)

        return bytes.fromhex(str_hex)

    def identify_all(self):
        """
        Send multicast request to identify ALL devices in current network interface
        and get information (name, ip) about them.
        :return: list with instances of class Device, an instance is created for each device found.
        """
        self.dst_mac = '01:0e:cf:00:00:00'
        self.frame, self.service, self.service_type = 0xfefe, dcp_header.IDENTIFY, dcp_header.REQUEST
        self.__send_request(0xFF, 0xFF, 0)
        return self.read_response()

    def identify(self, mac):
        """
        Get information (name, IP) about specific device in the network interface
        :param mac: MAC-address of the device to identify
        :return: instance of class Device
        """
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefe, dcp_header.IDENTIFY, dcp_header.REQUEST
        self.__send_request(0xFF, 0xFF, 0)
        response = self.read_response()
        if len(response) == 0:
            raise DcpTimeoutError
        return response[0]

    def set_ip_address(self, mac, ip_conf):
        """
        Set or change IP configurations of a specific device
        :param mac: MAC-address of target device
        :param ip_conf: list of strings in order ['ip address', 'subnet mask', 'router']
        :return: return message, Code 0 if no error occurred, 1-6 otherwise
        """
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefd, dcp_header.SET, dcp_header.REQUEST
        hex_addr = self.ip_to_hex(ip_conf)
        self.__send_request(DCPBlock.IP_ADDRESS[0], DCPBlock.IP_ADDRESS[1], len(hex_addr) + 2, hex_addr)
        time.sleep(2)
        response = self.read_response(set=True)
        if len(response) == 0:
            raise DcpTimeoutError
        return response

    def set_name_of_station(self, mac, name):
        """
        Set or change the name of station of a specific device
        :param mac: MAC-address of target device
        :param name: str with the name to set
        :return: return message, Code 0 if no error occurred, 1-6 otherwise
        """
        valid_pattern = re.compile(r"^[a-z][a-zA-Z0-9\-\.]*$")
        if not re.match(valid_pattern, name):
            raise ValueError('Name should correspond DNS standard. A string of invalid format provided.')
        name = name.lower()
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefd, dcp_header.SET, dcp_header.REQUEST
        self.__send_request(DCPBlock.NAME_OF_STATION[0], DCPBlock.NAME_OF_STATION[1], len(name) + 2,
                            bytes(name, encoding='ascii'))
        time.sleep(2)
        response = self.read_response(set=True)
        if len(response) == 0:
            raise DcpTimeoutError
        return response

    def get_ip_address(self, mac):
        """
        Get IP-address of a specific device
        :param mac: MAC-address of target device
        :return: IP-address (str)
        """
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefd, dcp_header.GET, dcp_header.REQUEST
        self.__send_request(DCPBlock.IP_ADDRESS[0], DCPBlock.IP_ADDRESS[1], 0)
        response = self.read_response()
        if len(response) == 0:
            raise DcpTimeoutError
        return response[0].IP

    def get_name_of_station(self, mac):
        """
        Get name of station of a specific device
        :param mac: MAC-address of target device
        :return: name of station (decoded str)
        """
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefd, dcp_header.GET, dcp_header.REQUEST
        self.__send_request(DCPBlock.NAME_OF_STATION[0], DCPBlock.NAME_OF_STATION[1], 0)
        response = self.read_response()
        if len(response) == 0:
            raise DcpTimeoutError
        return response[0].name_of_station

    def reset_to_factory(self, mac):
        '''
        Reset the communication parameters of the specified device to factory settings.
        :param mac: MAC-address of target device
        :return: return message, Code 0 if no error occurred, 1-6 otherwise
        '''
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefd, dcp_header.SET, dcp_header.REQUEST
        value = (4).to_bytes(2, 'big')
        self.__send_request(DCPBlock.RESET_TO_FACTORY[0], DCPBlock.RESET_TO_FACTORY[1], len(value) + 2, value)
        return self.read_response(set=True)

    def __send_request(self, opt, subopt, length, value=None):
        """
        Send DCP-package
        :param opt: Option of DCP data block in range 1 to 5
        :param subopt: Suboption of DCP data block
        :param length: length of DCP payload data, 0 if no data to send
        :param value: data to send, only used in 'set' functions
        """
        # Reopen the socket for each request. This avoids receiving outdated responses to another DCP instance in cases
        # where two or more instances are running on the same machine (i.e. with the same mac address).
        # Note: this does not help if the two instances make requests at the same time
        # This avoids processing outdated responses to other DCP instances with the same mac address
        # (most likely not a particularly common occurrence)
        self.reopen_socket()

        if not value:
            block_content = bytes()
        else:
            block_content = bytes([0x00, 0x01]) + value
            block_length = len(value) + 6 + (1 if len(value) % 2 == 1 else 0)
        block = DCPBlockRequest(opt, subopt, length, block_content)
        dcp = dcp_header(self.frame, self.service, self.service_type, 0x7010052, 0x0080,
                         block_length if value else len(block), payload=block)
        eth = eth_header(mac_to_hex(self.dst_mac), mac_to_hex(self.src_mac), 0x8892, payload=dcp)
        self.s.send(bytes(eth))

    @staticmethod
    def __response_set(payload):
        """
        Analyze DCP payload to identify if communication was successful, return error message otherwise.
        :param payload: byte string with DCP payload
        :return: error message, None if no error occurred, str otherwise
        """
        return_codes = {0: 'Code 00: Set successful',
                        1: 'Code 01: Option unsupported',
                        2: 'Code 02: Suboption unsupported or no DataSet available',
                        3: 'Code 03: Suboption not set',
                        4: 'Code 04: Resource Error',
                        5: 'Code 05: SET not possible by local reasons',
                        6: 'Code 06: In operation, SET not possible'}
        block_code = payload[6]
        if block_code != 0:
            return_message = '{}, SET unsuccessful'.format(return_codes[block_code])
            logging.warning(return_message)
        else:
            return_message = return_codes[block_code]
            logging.info(return_message)
        return return_message

    def read_response(self, to=10, set=False):
        """
        Receive packages in the network, filter DCP packages addressed to the current host and decode them
        :param to: timeout in sec
        :param set: this function was called inside a set-function, True enables error detection
        :return: string parameter if 'get', DCP payload if 'set', list with instances of class Device otherwise.
        """
        found = []
        try:
            timed_out = time.time() + to
            while time.time() < timed_out:
                try:
                    data = self.__receive_packet()
                except socket.timeout:
                    continue

                if data:
                    ret = self.__parse_dcp_packet(data, set)
                else:
                    continue
                if isinstance(ret, Device):
                    found.append(ret)
                elif isinstance(ret, str):
                    return ret
                elif not ret:
                    continue

        except TimeoutError:
            pass

        return found

    def __receive_packet(self):
        data = self.s.recv()
        if data is None:
            return
        data = bytes(data)
        return data

    def __parse_dcp_packet(self, data, set):
        """
        Process received byte-string and identify content parts
        :param data: byte-string of DCP-response, received by a socket
        :param set: bool-parameter to identify, if response is needed for a 'set'-function
        :return: message, if set was successful (if set); Device object otherwise
        """

        eth = eth_header(data)
        pro = self.__prove_for_validity(eth)
        if pro:
            blocks = pro.payload
            if set and blocks[0] == 5:
                msg = self.__response_set(blocks)
                return msg
            length = pro.len
            device = Device()
            device.MAC = hex_to_mac(eth.source)
            while length > 6:
                device, block_len = self.__process_block(blocks, device)
                blocks = blocks[block_len + 4:]
                length -= 4 + block_len

            return device
        else:
            return

    def __prove_for_validity(self, eth):
        """
        Check if the received packed is a DCP-response, addressed to the source
        :param eth: EtherhetHeader data
        :return: Ethernet payload if DCP-response addressed to the source, None otherwise
        """
        if hex_to_mac(eth.destination) != self.src_mac or eth.type != dcp_header.ETHER_TYPE:
            return
        pro = dcp_header(eth.payload)
        if not (pro.service_type == dcp_header.RESPONSE):
            return
        return pro

    @staticmethod
    def __process_block(blocks, device):
        """
        Process bytes of DCP data block and fill in a Device object with correspondent values
        :param blocks: byte content of a DCP data block
        :param device: instance of a Device object
        :return: filled instance of a Device object, length of DCP data block
        """
        block = DCPBlock(blocks)
        blockoption = (block.opt, block.subopt)
        block_len = block.len

        if blockoption == DCPBlock.NAME_OF_STATION:
            device.name_of_station = block.payload.rstrip(b'\x00').decode()
        elif blockoption == DCPBlock.IP_ADDRESS:
            device.IP = hex_to_ip(block.payload[0:4])
            device.netmask = hex_to_ip(block.payload[4:8])
            device.gateway = hex_to_ip(block.payload[8:12])
        elif blockoption == DCPBlock.DEVICE_FAMILY:
            device.family = block.payload.rstrip(b'\x00').decode()

        if block_len % 2 == 1:
            block_len += 1

        return device, block_len
