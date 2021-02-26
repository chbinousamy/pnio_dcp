from pnio_dcp.socket.winpcap import WinPcap, bpf_program, pcap_pkthdr
import ctypes
from scapy.all import conf


class PcapWrapper:
    def __init__(self, interface, timeout_ms=100):
        # TODO: convert network name to valid device name for pcapc

        # Open the pcap object
        self.pcap = WinPcap.pcap_open_live(interface, timeout_ms)
        # Set mintocopy to 0 to avoid buffering of packets within Npcap
        WinPcap.pcap_setmintocopy(self.pcap, 0)

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
