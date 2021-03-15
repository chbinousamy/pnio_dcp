from collections import namedtuple

from pnio_dcp.l2socket.winpcap import WinPcap, bpf_program, pcap_pkthdr, pcap_if, sockaddr_in, sockaddr_in6
import ctypes
import socket
from scapy.all import conf

IPv4Address = namedtuple("IPv4Address", ["port", "ip_address"])
IPv6Address = namedtuple("IPv6Address", ["port", "flow_info", "ip_address", "scope_id"])


class SocketAddress:
    """
    A python class corresponding to the sockaddr objects used by pcap.
    Describes the address of a socket, which consists of an address family (AF_INET for IPv4 or AF_INET6 für IPv6) and
    an address (either IPv4Address or IPv6Address depending on the family).
    """
    def __init__(self, socket_address_p):
        """
        Create new SocketAddress by parsing a given sockaddr object.
        :param socket_address_p: Pointer to the sockaddr to parse.
        :type socket_address_p: Pointer(sockaddr)
        """
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
        """
        Helper function to parse an IP address (IPv4 or IPv6) from bytes to string.
        :param ip_address: The IP address as bytes array.
        :type ip_address: ctypes.c_ubyte array
        :return: The IP address as string.
        :rtype: string
        """
        if self.address_family == socket.AF_INET:
            return '.'.join([str(group) for group in ip_address])
        elif self.address_family == socket.AF_INET6:
            return ':'.join([f"{group:x}" for group in ip_address])

    def __str__(self):
        """
        Convert this socket address to a human-readable string.
        :return: String representation of the address.
        :rtype: string
        """
        return f"SocketAddress[address_family={self.address_family}, address={self.address}]"


class PcapAddress:
    """
    A python class corresponding to the pcap_addr objects used by pcap.
    Consists of a (mandatory) address and optionally, a netmask, broadcast address and destination address.
    All addresses are represented as SocketAddress.
    """
    def __init__(self, pcap_addr):
        """
        Create new PcapAddress by parsing a given pcap_addr object.
        :param pcap_addr: Pointer to the pcap_addr to parse.
        :type pcap_addr: POINTER(pcap_addr)
        """
        self.address = self.__parse_address(pcap_addr.contents.addr)
        self.netmask = self.__parse_address(pcap_addr.contents.netmask)
        self.broadcast_address = self.__parse_address(pcap_addr.contents.broadaddr)
        self.destination_address = self.__parse_address(pcap_addr.contents.dstaddr)

    @staticmethod
    def __parse_address(address_pointer):
        """
        Helper function to parse an address or set it to None is cases of a nullpointer.
        :param address_pointer: Pointer to the sockaddr object to parse.
        :type address_pointer: POINTER(sockaddr)
        :return: The parsed address or None if given a nullpointer.
        :rtype: Optional(SocketAddress)
        """
        return SocketAddress(address_pointer) if address_pointer else None

    def __str__(self):
        """
        Convert this address to a human-readable string.
        :return: String representation of the address.
        :rtype: string
        """
        return f"PcapAddress[address={self.address}, netmask={self.netmask}, " \
               f"broadcast_address={self.broadcast_address}, destination_address={self.destination_address}]"


class PcapDevice:
    """
    A python class corresponding to the pcap_if objects used by pcap to describe network devices.
    A device consists of a name, an optional description, a list of addresses (of type PcapAddress), and some flags.
    """
    def __init__(self, pcap_if_p):
        """
        Create new PcapDevice by parsing a given pcap_if object.
        :param pcap_if_p: Pointer to the pcap_if object to parse.
        :type pcap_if_p: POINTER(pcap_if)
        """
        pcap_device = pcap_if_p.contents

        self.name = pcap_device.name.decode()
        self.description = pcap_device.description.decode() if pcap_device.description else ""

        self.addresses = []
        next_address = pcap_device.addresses
        while next_address:
            address = PcapAddress(next_address)
            self.addresses.append(address)
            next_address = next_address.contents.next

        self.flags = pcap_device.flags  # as of now, the flags are not parsed as this is not necessary for the dcp lib

    def __str__(self):
        """
        Convert this device to a human-readable string.
        :return: String representation of the device.
        :rtype: string
        """
        return f"PcapDevice[name='{self.name}', description='{self.description}', " \
               f"addresses={[str(addr) for addr in self.addresses]}, flags={self.flags}]"


class PcapWrapper:
    """A wrapper to WinPcap/Npcap with all necessary functions to simulate an L2-Socket on Windows."""

    def __init__(self, device_name, timeout_ms=100):
        """
        Open a pcap capture for the given network device.
        :param device_name: The name of the network device, use e.g. get_device_name_from_ip or get_all_devices to find
        the correct name.
        :type device_name: string
        :param timeout_ms: The read timeout in milliseconds (use 0 for no timeout). Default is 100ms.
        :type timeout_ms: Optional(int)
        """
        # Open the pcap object
        self.pcap = WinPcap.pcap_open_live(device_name, timeout_ms)
        # Set mintocopy to 0 to avoid buffering of packets within Npcap
        WinPcap.pcap_setmintocopy(self.pcap, 0)

    @staticmethod
    def get_device_name_from_ip(ip):
        """
        Determine the device name expected by pcap for the device with the given ip.
        :param ip: The ip to search for (both IPv4 and IPv6 are possible)
        :type ip: string
        :return: The device name or None if no such devices was found.
        :rtype: Optional(string)
        """
        def filter_by_ip(device):
            for address in device.addresses:
                if address.address.address.ip_address == ip:
                    return True
            return False

        devices = PcapWrapper.get_all_devices()
        devices = [device for device in devices if filter_by_ip(device)]

        if not devices:
            return None
        else:
            return devices[0].name

    @staticmethod
    def get_all_devices():
        """
        Get a list of all network devices that can be opened by pcap_open_live (e.g. with the PcapWrapper constructor).
        :return: The list of all network devices found by pcap (might be empty). In case of an error, None is returned.
        :rtype: Optional(List(PcapDevice))
        """
        devices = ctypes.POINTER(pcap_if)()
        result, error_message = WinPcap.pcap_findalldevs(devices)

        if result != 0:
            return None

        parsed_devices = []
        next_device = devices
        while next_device:
            device = PcapDevice(next_device)
            parsed_devices.append(device)
            next_device = next_device.contents.next

        return parsed_devices

    def get_next_packet(self):
        """
        Receive the next packet with Pcap.
        :return: The received packet, None in cases of an error or timeout.
        :rtype: Optional(bytes)
        """
        header = ctypes.POINTER(pcap_pkthdr)()
        pkt_data = ctypes.POINTER(ctypes.c_ubyte)()
        result = WinPcap.pcap_next_ex(self.pcap, header, pkt_data)

        if result <= 0:  # error or timeout
            return None
        # extract and return the packet data
        return bytes(bytearray(pkt_data[:header.contents.len]))

    def set_bpf_filter(self, bpf_filter):
        """
        Set a BPF filter to filter the packets received by pcap.
        :param bpf_filter: A BPF filter expression.
        :type bpf_filter: string
        :return: Whether the filter was set successfully.
        :rtype: boolean
        """
        # Compile the filter to a bpf program
        program = bpf_program()
        result = WinPcap.pcap_compile(self.pcap, program, bpf_filter)
        if result != 0:  # Error compiling
            return False

        # Set the compiled bpf program as filter and return whether the filter was set successfully
        return WinPcap.pcap_setfilter(self.pcap, program) == 0

    def send(self, packet):
        """
        Send a given packet with Pcap.
        :param packet: The raw packet.
        :type packet: bytes
        :return: Whether the packet was send successfully.
        :rtype: boolean
        """
        return WinPcap.pcap_sendpacket(self.pcap, packet, len(packet)) == 0

    def close(self):
        """Close this pcap capture."""
        WinPcap.pcap_close(self.pcap)


class L2pcapSocket:

    def __init__(self, ip=None, interface=None, filter=None):
        pcap_device_name = PcapWrapper.get_device_name_from_ip(ip)
        self.pcap = PcapWrapper(pcap_device_name)
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
    def __init__(self, ip=None, interface=None, filter=None):
        self.__s = conf.L2socket(iface=interface, filter=filter)

    def send(self, data):
        self.__s.send(data)

    def recv(self):
        return self.__s.recv()
