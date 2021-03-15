from pnio_dcp.l2socket.pcap_wrapper import PcapWrapper
from scapy.all import conf


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
