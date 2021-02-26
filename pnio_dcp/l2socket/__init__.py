import pnio_dcp.l2socket.winpcap
from pnio_dcp.l2socket.l2socket import PcapWrapper

if __name__ == "__main__":
    # Set this to the device name expected by Pcap
    # VM specific, use the Transport Name  given by running 'getmac'
    interface = "\Device\Tcpip_{D4FCCF07-288F-4499-916B-4F2286058053}"
    pcap = PcapWrapper(interface)
