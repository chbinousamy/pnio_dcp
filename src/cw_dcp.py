import sys
sys.path.insert(0, '../src')
from scapy.all import *
from profinet_dcp.dcp import *
from profinet_dcp.util import *
from profinet_dcp.protocol import *
import binascii


class Device:

    NameOfStation = ''
    MAC = ''
    IP = ''
    Netmask = ''
    Gateway = ''


class CodewerkDCP:
    def __init__(self, iface):
        self.devices = []
        self.dst_mac = ''
        self.iface = iface
        # self.src_mac = Ether().src  # 00:50:56:ac:28:4e
        self.src_mac = '00:50:56:ac:dd:2e'
        self.s = conf.L2socket(iface=iface)

    def identify_all(self):
        self.dst_mac = '01:0e:cf:00:00:00'
        self.send_request(0xFF, 0xFF, 0)
        return self.read_response()

    def identify(self, mac, opt, subopt, length):
        self.dst_mac = mac
        self.send_request(opt, subopt, length)
        return self.read_response()

    def send_request(self, opt, subopt, length):
        block = PNDCPBlockRequest(opt, subopt, length, bytes())
        dcp = PNDCPHeader(0xfefe, PNDCPHeader.IDENTIFY, PNDCPHeader.REQUEST, 0x7010052, 0x0080, len(block), payload=block)
        eth = EthernetVLANHeader(s2mac(self.dst_mac), s2mac(self.src_mac), 0x8892, payload=dcp)

        self.s.send(bytes(eth))

    def read_response(self, to=20, once=False, debug=True):
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
                    print()
                    debug and print("MAC address:", mac2s(eth.src))

                    pro = PNDCPHeader(eth.payload)
                    if not (pro.service_type == PNDCPHeader.RESPONSE):
                        continue

                    blocks = pro.payload
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
                        elif blockoption == PNDCPBlock.IP_ADDRESS:
                            debug and print(str(block.parse_ip()))
                            print(str(block.parse_ip()))
                            parsed["ip"] = s2ip(block.payload[0:4])
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

        return found
