import sys
import os
myPath = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, myPath + '/../src')
# sys.path.insert(0, '../src')
from scapy.all import *
from profinet_dcp.util import *
from profinet_dcp.protocol import *
import binascii
import logging


class Device:

    NameOfStation = ''
    MAC = ''
    IP = ''
    Netmask = ''
    Gateway = ''


class CodewerkDCP:
    def __init__(self, iface, mac):
        self.devices = []
        self.dst_mac = ''
        # self.iface = conf.route.route(ip)[0]
        self.iface = iface
        # self.src_mac = Ether().src  # 00:50:56:ac:28:4e
        self.src_mac = mac
        self.s = conf.L2socket(iface=iface)

        self.frame = None
        self.service = None
        self.service_type = None

    def ip_to_hex(self, ip_conf):
        str_hex = ''
        for param in ip_conf:
            nums = list(param.split('.'))
            for i in nums:
                str_hex += hex(int(i))[2:].zfill(2)
        return bytes.fromhex(str_hex)

    def identify_all(self):
        self.dst_mac = '01:0e:cf:00:00:00'
        self.frame, self.service, self.service_type = 0xfefe, PNDCPHeader.IDENTIFY, PNDCPHeader.REQUEST
        self.send_request(0xFF, 0xFF, 0)
        return self.read_response()

    def identify(self, mac):
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefe, PNDCPHeader.IDENTIFY, PNDCPHeader.REQUEST
        self.send_request(0xFF, 0xFF, 0)
        return self.read_response()[0]

    def set_ip_address(self, mac, ip_conf):
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefd, PNDCPHeader.SET, PNDCPHeader.REQUEST
        hex_addr = self.ip_to_hex(ip_conf)
        self.send_request(PNDCPBlock.IP_ADDRESS[0], PNDCPBlock.IP_ADDRESS[1], len(hex_addr)+2, hex_addr)
        time.sleep(2)
        return self.read_response(once=True, debug=False, get=False, set=True)

    def set_name_of_station(self, mac, name):
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefd, PNDCPHeader.SET, PNDCPHeader.REQUEST
        self.send_request(PNDCPBlock.NAME_OF_STATION[0], PNDCPBlock.NAME_OF_STATION[1], len(name)+2, bytes(name, encoding='ascii'))
        time.sleep(2)
        return self.read_response(once=True, debug=False, get=False, set=True)

    def get_ip_address(self, mac):
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefd, PNDCPHeader.GET, PNDCPHeader.REQUEST
        self.send_request(PNDCPBlock.IP_ADDRESS[0], PNDCPBlock.IP_ADDRESS[1], 0)
        # return list(self.read_response(once=True, debug=False, get=True).values())[0]['ip']
        return self.read_response(once=True, debug=False, get=True)

    def get_name_of_station(self, mac):
        self.dst_mac = mac
        self.frame, self.service, self.service_type = 0xfefd, PNDCPHeader.GET, PNDCPHeader.REQUEST
        self.send_request(PNDCPBlock.NAME_OF_STATION[0], PNDCPBlock.NAME_OF_STATION[1], 0)
        # return list(self.read_response(once=True, debug=False, get=True).values())[0]['name'].decode()
        return self.read_response(once=True, debug=False, get=True).decode()

    def send_request(self, opt, subopt, length, value=None):
        if not value:
            block_content = bytes()
        else:
            block_content = bytes([0x00, 0x01]) + value
            block_length = len(value) + 6 + (1 if len(value) % 2 == 1 else 0)
        block = PNDCPBlockRequest(opt, subopt, length, block_content)
        dcp = PNDCPHeader(self.frame, self.service, self.service_type, 0x7010052, 0x0080, block_length if value else len(block), payload=block)
        eth = EthernetVLANHeader(s2mac(self.dst_mac), s2mac(self.src_mac), 0x8892, payload=dcp)
        self.s.send(bytes(eth))

    def response_get_identify(self, payload, once=False, debug=True, get=False):
        pass

    def response_set(self, payload):
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

    def read_response(self, to=20, once=False, debug=True, get=False, set=False):
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
                        msg = self.response_set(blocks)
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
