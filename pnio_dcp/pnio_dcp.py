"""
Copyright (c) 2020 Codewerk GmbH, Karlsruhe.
All Rights Reserved.
"""
import logging
import random
import re
import socket
import time

import psutil
from scapy.all import conf

from .error import DcpTimeoutError
from .protocol import dcp_header, eth_header, DCPBlock, DCPBlockRequest
from .util import mac_to_hex, hex_to_mac, hex_to_ip


logger = logging.getLogger(__name__)


class Device:
    """A DCP device defined by its properties (name of station, mac address, ip address etc.)."""
    name_of_station = ''
    MAC = ''
    IP = ''
    netmask = ''
    gateway = ''
    family = ''


class DCP:
    def __init__(self, ip):
        """
        Create a new instance, use the given ip to select the network interface.
        :param ip: The ip address used to select the network interface.
        :type ip: string
        """
        self.devices = []
        self.dst_mac = ''
        self.src_mac, self.iface = self.__get_nic(ip)

        # the XID is the id of the current transaction and can be used to identify the responses to a request
        self.xid = int(random.getrandbits(32))  # initialize it with a random value

        # This filter in BPF format filters all unrelated packets (i.e. wrong mac address or ether type) before they are
        # processed by scapy. This solves issues in high traffic networks, as scapy is known to miss packets under heavy
        # load. See e.g. here: https://scapy.readthedocs.io/en/latest/usage.html#performance-of-scapy
        self.socket_filter = f"ether host {self.src_mac} and ether proto {dcp_header.ETHER_TYPE}"

        self.s = conf.L2socket(iface=self.iface, filter=self.socket_filter)
        self.frame = None
        self.service = None
        self.service_type = None

    def reopen_socket(self):
        """Close and reopen the L2 socket used to send and receive DCP packets."""
        self.s.close()
        self.s = conf.L2socket(iface=self.iface, filter=self.socket_filter)

    @staticmethod
    def __get_nic(ip):
        """
        Get the mac address and name of the network interface corresponding to the given IP address by iterating over
        all available network interfaces and comparing the IP addresses.
        If no interface with the given IP address is found, a ValueError is raised.
        :param ip: The IP address to select the network interface with.
        :type ip: string
        :return: MAC-address, Interface name [or None if no interface with the given IP address is found]
        :rtype: Tuple[string, string]
        """
        addrs = psutil.net_if_addrs()
        for iface_name, config in addrs.items():
            iface_mac = config[0][1]
            iface_ip = config[1][1]
            if iface_ip == ip:
                return iface_mac.replace('-', ':').lower(), iface_name
        raise ValueError(f"Could not find a network interface for ip {ip}")

    @staticmethod
    def ip_to_hex(ip_conf):
        """
        Converts a list containing strings with IP-address, subnet mask and router into byte-string.
        :param ip_conf: list of strings in order ['ip address', 'subnet mask', 'router']
        :type ip_conf: List[string]
        :return: string of bytes, the content of ip_conf has been converted to hex and joined together.
        :rtype: bytes
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
        Send multicast request to identify ALL devices in current network interface and get information about them.
        :return: A list containing all devices found.
        :rtype: List[Device]
        """
        self.dst_mac = '01:0e:cf:00:00:00'
        self.frame, self.service, self.service_type = 0xfefe, dcp_header.IDENTIFY, dcp_header.REQUEST
        self.__send_request(0xFF, 0xFF, 0)
        return self.read_response()

    def identify(self, mac):
        """
        Send a request to get information about specific device with the given mac address in the network interface.
        :param mac: MAC-address of the device to identify (as ':' separated string)
        :type mac: string
        :return: The requested device.
        :rtype: Device
        """
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefe, dcp_header.IDENTIFY, dcp_header.REQUEST
        self.__send_request(0xFF, 0xFF, 0)
        response = self.read_response()
        if len(response) == 0:
            logger.debug(f"Timeout: no answer from device with MAC {mac}")
            raise DcpTimeoutError
        return response[0]

    def set_ip_address(self, mac, ip_conf):
        """
        Send a request to set or change the IP configuration of the device with the given mac address.
        :param mac: mac address of the target device (as ':' separated string)
        :type mac: string
        :param ip_conf: list containing the values to set for the ip address, subnet mask, and router in that order.
        :type ip_conf: List[string]
        :return: return message, Code 0 if no error occurred, 1-6 otherwise (see __response_set for the actual format)
        :rtype: string
        """
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefd, dcp_header.SET, dcp_header.REQUEST
        hex_addr = self.ip_to_hex(ip_conf)
        block_qualifier = bytes([0x00, 0x01])  # set BlockQualifier to 'Save the value permanent (1)'
        self.__send_request(DCPBlock.IP_ADDRESS[0], DCPBlock.IP_ADDRESS[1], len(hex_addr) + 2,
                            block_qualifier + hex_addr)
        time.sleep(2)
        response = self.read_response(set=True)
        if len(response) == 0:
            logger.debug(f"Timeout: no answer from device with MAC {mac}")
            raise DcpTimeoutError
        return response

    def set_name_of_station(self, mac, name):
        """
        Send a request to set or change the name of station of the device with the given mac address.
        :param mac: mac address of the target device (as ':' separated string)
        :type mac: string
        :param name: The new name to be set.
        :type name: string
        :return: return message, Code 0 if no error occurred, 1-6 otherwise (see __response_set for the actual format)
        :rtype: string
        """
        valid_pattern = re.compile(r"^[a-z][a-zA-Z0-9\-\.]*$")
        if not re.match(valid_pattern, name):
            raise ValueError('Name should correspond DNS standard. A string of invalid format provided.')
        name = name.lower()
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefd, dcp_header.SET, dcp_header.REQUEST
        block_qualifier = bytes([0x00, 0x01])  # set BlockQualifier to 'Save the value permanent (1)'
        self.__send_request(DCPBlock.NAME_OF_STATION[0], DCPBlock.NAME_OF_STATION[1], len(name) + 2,
                            block_qualifier + bytes(name, encoding='ascii'))
        time.sleep(2)
        response = self.read_response(set=True)
        if len(response) == 0:
            logger.debug(f"Timeout: no answer from device with MAC {mac}")
            raise DcpTimeoutError
        return response

    def get_ip_address(self, mac):
        """
        Send a request to get the IP address of the device with the given mac address.
        :param mac: mac address of the target device (as ':' separated string)
        :type mac: string
        :return: The requested IP-address.
        :rtype: string
        """
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefd, dcp_header.GET, dcp_header.REQUEST
        self.__send_request(DCPBlock.IP_ADDRESS[0], DCPBlock.IP_ADDRESS[1], 0)
        response = self.read_response()
        if len(response) == 0:
            logger.debug(f"Timeout: no answer from device with MAC {mac}")
            raise DcpTimeoutError
        return response[0].IP

    def get_name_of_station(self, mac):
        """
        Send a request to get the name of station of the device with the given mac address.
        :param mac: mac address of the target device (as ':' separated string)
        :type mac: string
        :return: The requested name of station.
        :rtype: string
        """
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefd, dcp_header.GET, dcp_header.REQUEST
        self.__send_request(DCPBlock.NAME_OF_STATION[0], DCPBlock.NAME_OF_STATION[1], 0)
        response = self.read_response()
        if len(response) == 0:
            logger.debug(f"Timeout: no answer from device with MAC {mac}")
            raise DcpTimeoutError
        return response[0].name_of_station

    def reset_to_factory(self, mac):
        """
        Send a request to reset the communication parameters of the device with the given mac address to its factory
        settings.
        :param mac: mac address of the target device (as ':' separated string)
        :type mac: string
        :return: return message, Code 0 if no error occurred, 1-6 otherwise (see __response_set for the actual format)
        :rtype: string
        """
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefd, dcp_header.SET, dcp_header.REQUEST
        value = (4).to_bytes(2, 'big')
        self.__send_request(DCPBlock.RESET_TO_FACTORY[0], DCPBlock.RESET_TO_FACTORY[1], len(value), value)
        time.sleep(2)
        response = self.read_response(set=True)
        if len(response) == 0:
            logger.debug(f"Timeout: no answer from device with MAC {mac}")
            raise DcpTimeoutError
        return response

    def __send_request(self, opt, subopt, length, value=None):
        """
        Send a DCP request with the given option and sub-option and an optional payload (the given value)
        :param opt: The option of the DCP data block, see DCP specification for more infos.
        :type opt: int
        :param subopt: The sub-option of the DCP data block, see DCP specification for more infos.
        :type subopt: int
        :param length: The length of DCP payload data, should be 0 if no data is sent.
        :type length: int
        :param value: The DCP payload data to send, only used in 'set' functions
        :type value: bytes
        """
        # Reopen the socket for each request. This avoids receiving outdated responses to another DCP instance in cases
        # where two or more instances are running on the same machine (i.e. with the same mac address).
        # Note: this does not help if the two instances make requests at the same time
        # This avoids processing outdated responses to other DCP instances with the same mac address
        # (most likely not a particularly common occurrence)
        self.reopen_socket()
        self.xid += 1  # increment the XID wih each request (used to identify a transaction)

        block_content = value if value else bytes()
        if len(block_content) % 2:  # if the block content has odd length, add one byte padding at the end
            block_content += bytes([0x00])
        block = DCPBlockRequest(opt, subopt, length, block_content)

        dcp = dcp_header(self.frame, self.service, self.service_type, self.xid, 0x0080, len(block), payload=block)
        eth = eth_header(mac_to_hex(self.dst_mac), mac_to_hex(self.src_mac), 0x8892, payload=dcp)
        self.s.send(bytes(eth))

    @staticmethod
    def __response_set(payload):
        """
        Analyze the payload of a DCP response to a set request to extract return code (used to determine if the
        communication was successful) Return a return message describing the result.
        :param payload: The DCP payload to analyze.
        :type payload: bytes
        :return: A return message describing the result.
        :rtype: string
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
            logger.warning(return_message)
        else:
            return_message = return_codes[block_code]
            logger.debug(return_message)
        return return_message

    def read_response(self, to=10, set=False):
        """
        Receive packets and parse the response:
        - receive packets on the L2 socket addressed to the specified host mac address
        - filter the packets to process only valid DCP responses to the current request
        - decode and parse these responses
        - if the response is a device, append it to the list of found devices and continue with the next packet
        - if the response if a string (return message to set request) return it immediately
        - repeat this until a string response is received or the timeout occurs.
        :param to: Timeout in seconds
        :type to: integer
        :param set: Whether this function was called inside a set-function. True enables error detection. Default: False
        :type set: boolean
        :return: If set: return message, otherwise: list of devices (might be empty if no device was found)
        :rtype: Union[List[Device], string]
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
        """
        Receive a packet on the L2 socket addressed to the specified host mac address and convert it to bytes.
        Might return None if no data is received.
        :return: The received packet as bytes or None if no data was received.
        :rtype: Optional[bytes]
        """
        data = self.s.recv()
        if data is None:
            return
        data = bytes(data)
        return data

    def __parse_dcp_packet(self, data, set):
        """
        Validate and parse a received ethernet packet (given via the data parameter):
        Parse the data as ethernet packet, check if it is a valid DCP response and convert it to a dcp_header object.
        Then, parse to DCP payload to extract and return the response value.
        If this the response to a set requests (i.e. the set parameter is True): the response message is extracted
        using __response_set. This message is then returned.
        Otherwise: a Device object is constructed from the response which is then returned.
        If the response is invalid, None is returned.
        :param data: The DCP response received by the socket.
        :type data: bytes
        :param set: Whether this function was called inside a set-function.
        :type set: boolean
        :return: Valid response: if set request: response message, otherwise: Device object. Invalid response: None
        :rtype: Optional[Union[string, Device]]
        """
        # Parse the data as ethernet packet.
        eth = eth_header(data)

        # Check if the packet is a valid DCP response to the latest request and convert the ethernet payload to a
        # dcp_header object
        pro = self.__prove_for_validity(eth)

        if pro:  # if this is a valid DCP response
            # parse the DCP blocks in the payload
            blocks = pro.payload

            # If called inside a set request and the option of the response is 5 ('Control'): parse the response message
            if set and blocks[0] == 5:
                msg = self.__response_set(blocks)
                return msg

            # Otherwise, extract a device from the DCP payload
            length = pro.len
            device = Device()
            device.MAC = hex_to_mac(eth.source)
            # Process each DCP data block in the payload and modify the attributes of the device accordingly
            while length > 6:
                device, block_len = self.__process_block(blocks, device)
                blocks = blocks[block_len + 4:]  # advance to the start of the next block
                length -= 4 + block_len

            return device
        else:  # return None for invalid packets
            return

    def __prove_for_validity(self, eth):
        """
        Check and parse the given ethernet packet.
        Check if the received packed is a valid DCP-response to the last request. That is: it is addressed to this
        src_mac address, has the correct ether type, has the service type for 'response', and the XID of the last
        request.
        If the response is valid, return the ethernet payload as dcp_header object. Otherwise, None is returned.
        :param eth: The ethernet packet to validate and parse.
        :type eth: eth_header
        :return: The ethernet payload as dcp_header object if the response is valid, None otherwise.
        :rtype: Optional[dcp_header]
        """
        if hex_to_mac(eth.destination) != self.src_mac or eth.type != dcp_header.ETHER_TYPE:
            return
        pro = dcp_header(eth.payload)
        if not (pro.service_type == dcp_header.RESPONSE):
            return
        if pro.xid != self.xid:
            logger.debug(f"Ignoring valid DCP packet with incorrect XID: {hex(pro.xid)} != {hex(self.xid)}")
            return
        return pro

    @staticmethod
    def __process_block(blocks, device):
        """
        Extract and parse the first DCP data block in the given payload data and fill the given Device object with the
        extracted values.
        :param blocks: The DCP payload to process. Must contain a valid DCP data block as prefix, all data after the
        first complete block is ignored.
        :type blocks: bytes
        :param device: The Device object to be filled.
        :type device: Device
        :return: The modified Device object and the length of the processed DCP data block
        :rtype: Device, int
        """
        # Extract the first DCPBlock from the given payload.
        # Other blocks may follow after the first, they are ignored by this method.
        block = DCPBlock(blocks)

        # use the option and sub-option to determine which value is encoded in the current block
        # then, extract the value accordingly, decode it and set the corresponding attribute of the device
        block_option = (block.opt, block.subopt)
        if block_option == DCPBlock.NAME_OF_STATION:
            device.name_of_station = block.payload.rstrip(b'\x00').decode()
        elif block_option == DCPBlock.IP_ADDRESS:
            device.IP = hex_to_ip(block.payload[0:4])
            device.netmask = hex_to_ip(block.payload[4:8])
            device.gateway = hex_to_ip(block.payload[8:12])
        elif block_option == DCPBlock.DEVICE_FAMILY:
            device.family = block.payload.rstrip(b'\x00').decode()

        # round up the block length to the next even number
        block_len = block.len + (block.len % 2)

        # Return the modified device and the length of the processed block
        return device, block_len
