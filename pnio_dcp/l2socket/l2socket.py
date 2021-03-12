from collections import namedtuple

from pnio_dcp.l2socket.winpcap import WinPcap, bpf_program, pcap_pkthdr
from pnio_dcp.l2socket.winpcap import sockaddr_in, sockaddr_in6
import ctypes
import socket
from scapy.all import conf

IPv4Address = namedtuple("IPv4Address", ["port", "ip_address"])
IPv6Address = namedtuple("IPv6Address", ["port", "flow_info", "ip_address", "scope_id"])


class SocketAddress:
    def __init__(self, socket_address_p):
        # get address family (AF_INET for IPv4 or AF_INET6 für IPv6) from the general sockaddr type
        self.address_family = socket_address_p.contents.sa_family

        # cast the sockaddr to the corresponding specialized sockaddr type and extract the address information
        self.address = None
        if self.address_family == socket.AF_INET:
            socket_address = ctypes.cast(socket_address_p, ctypes.POINTER(sockaddr_in)).contents
            port = socket_address.sin_port
            ip_address = self.__parse_ip_address(socket_address.sin_addr)
            self.address = IPv4Address(port, ip_address)
        elif self.address_family == socket.AF_INET6:
            socket_address = ctypes.cast(socket_address_p, ctypes.POINTER(sockaddr_in6)).contents
            port = socket_address.sin6_port
            flow_info = socket_address.sin6_flowinfo
            scope_id = socket_address.sin6_scope_id
            ip_address = self.__parse_ip_address(socket_address.sin6_addr)
            self.address = IPv6Address(port, flow_info, ip_address, scope_id)

    def __parse_ip_address(self, ip_address):
        if self.address_family == socket.AF_INET:
            return '.'.join([str(group) for group in ip_address])
        elif self.address_family == socket.AF_INET6:
            return ':'.join([f"{group:x}" for group in ip_address])

    def __str__(self):
        return f"SocketAddress[address_family={self.address_family}, address={self.address}]"


class PcapAddress:
    def __init__(self, pcap_addr):
        self.address = self.__parse_address(pcap_addr.contents.addr)
        self.netmask = self.__parse_address(pcap_addr.contents.netmask)
        self.broadcast_address = self.__parse_address(pcap_addr.contents.broadaddr)
        self.destination_address = self.__parse_address(pcap_addr.contents.dstaddr)

    @staticmethod
    def __parse_address(address_pointer):
        return SocketAddress(address_pointer) if address_pointer else None

    def __str__(self):
        return f"PcapAddress[address={self.address}, netmask={self.netmask}, " \
               f"broadcast_address={self.broadcast_address}, destination_address={self.destination_address}]"


class PcapDevice:
    def __init__(self, pcap_if_p):
        pcap_if = pcap_if_p.contents

        self.name = pcap_if.name.decode()
        self.description = pcap_if.description.decode() if pcap_if.description else ""

        self.addresses = []
        next_address = pcap_if.addresses
        while next_address:
            address = PcapAddress(next_address)
            self.addresses.append(address)
            next_address = next_address.contents.next

        self.flags = pcap_if.flags  # as of now, the flags are not parsed as this is not necessary for the dcp lib

    def __str__(self):
        return f"PcapDevice[name='{self.name}', description='{self.description}', " \
               f"addresses={[str(addr) for addr in self.addresses]}, flags={self.flags}]"


class PcapWrapper:
    def __init__(self, interface, timeout_ms=100):
        # TODO: convert network name to valid device name for pcapc

        # Open the pcap object
        self.pcap = WinPcap.pcap_open_live(interface, timeout_ms)
        # Set mintocopy to 0 to avoid buffering of packets within Npcap
        WinPcap.pcap_setmintocopy(self.pcap, 0)

    @staticmethod
    def get_all_devices():
        devices = WinPcap.pcap_get_all_devices()
        if devices is None:
            return None

        parsed_devices = []
        next_device = devices
        while next_device:
            device = PcapDevice(next_device)
            parsed_devices.append(device)
            next_device = next_device.contents.next

        return parsed_devices

    def get_next_packet(self):
        header = ctypes.POINTER(pcap_pkthdr)()
        pkt_data = ctypes.POINTER(ctypes.c_ubyte)()
        result = WinPcap.pcap_next_ex(self.pcap, header, pkt_data)

        if result <= 0:  # error or timeout
            return None
        # extract and return the packet data
        return bytes(bytearray(pkt_data[:header.contents.len]))

    def set_bpf_filter(self, bpf_filter):
        # Compile the filter to a bpf program
        program = bpf_program()
        result = WinPcap.pcap_compile(self.pcap, program, bpf_filter)
        if result != 0:  # Error compiling
            return False

        # Set the compiled bpf program as filter and return whether the filter was set successfully
        return WinPcap.pcap_setfilter(self.pcap, program) == 0

    def send(self, packet):
        WinPcap.pcap_sendpacket(self.pcap, packet, len(packet))

    def close(self):
        WinPcap.pcap_close(self.pcap)


class L2pcapSocket:

    def __init__(self, interface, filter=None):
        self.pcap = PcapWrapper(interface)
        if filter:
            self.pcap.set_bpf_filter(filter)

    def recv(self):
        # Receive the next packet from pcap
        return self.pcap.get_next_packet()

    def send(self, data):
        self.pcap.send(bytes(data))

    def close(self):
        self.pcap.close()


class L2ScapySocket:
    def __init__(self, iface=None, filter=None):
        self.__s = conf.L2socket(iface=iface, filter=filter)

    def send(self, data):
        self.__s.send(data)

    def recv(self):
        return self.__s.recv()
