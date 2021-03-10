import ctypes
import os
import pathlib

# Load Pcap DLL from Windows/System32/Npcap
npcap_path = pathlib.Path(os.environ["WINDIR"], "System32", "Npcap")
ctypes.CDLL(str(npcap_path / "Packet.dll"))
dll = ctypes.CDLL(str(npcap_path / "wpcap.dll"))
_lib = dll

# Define all necessary structs and type aliases
bpf_u_int32 = ctypes.c_uint32
pcap_t = ctypes.c_void_p
u_char = ctypes.c_ubyte
c_string = ctypes.c_char_p
null_pointer = ctypes.POINTER(ctypes.c_int)()

# Structures for the structs used as in- or output types of the functions imported from the pcap DLL
# The this application, necessary structures are: bpf_program with bpf_insn, and pcap_pkthdr with timeval


class bpf_insn(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort),
                ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte),
                ("k", ctypes.c_int)]


class bpf_program(ctypes.Structure):
    _fields_ = [('bf_len', ctypes.c_int),
                ('bf_insns', ctypes.POINTER(bpf_insn))]


class timeval(ctypes.Structure):
    _fields_ = [('tv_sec', ctypes.c_long),
                ('tv_usec', ctypes.c_long)]


class pcap_pkthdr(ctypes.Structure):
    _fields_ = [('ts', timeval),
                ('caplen', bpf_u_int32),
                ('len', bpf_u_int32)]


class sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort),
                ("sa_data", ctypes.c_int16)]


class sockaddr_in(ctypes.Structure):
    _fields_ = [("sin_family", ctypes.c_ushort),
                ("sin_port", ctypes.c_uint16),
                ("sin_addr", ctypes.c_int8)]


class pcap_addr(ctypes.Structure):
    pass


pcap_addr._fields_ = [('next', ctypes.POINTER(pcap_addr)),
                      ('addr', ctypes.POINTER(sockaddr_in)),
                      ('netmask', ctypes.POINTER(sockaddr_in)),
                      ('broadaddr', ctypes.POINTER(sockaddr_in)),
                      ('dstaddr', ctypes.POINTER(sockaddr_in))]


class pcap_if(ctypes.Structure):
    pass


pcap_if._fields_ = [('pcap_if', ctypes.POINTER(pcap_if)),
                    ('name', c_string),
                    ('description', c_string),
                    ('addresses', ctypes.POINTER(pcap_addr)),
                    ('flags', ctypes.c_uint)]


# Import all necessary functions from the DLL and set their argument and return types
# The following functions are imported:
#   - pcap_open_live
#   - pcap_setmintocopy
#   - pcap_close
#   - pcap_next_ex
#   - pcap_sendpacket
#   - pcap_compile
#   - pcap_setfilter

_pcap_open_live = dll.pcap_open_live
_pcap_open_live.argtypes = [c_string, ctypes.c_int, ctypes.c_int, ctypes.c_int, c_string]
_pcap_open_live.restype = ctypes.POINTER(pcap_t)

_pcap_setmintocopy = dll.pcap_setmintocopy
_pcap_setmintocopy.argtype = [ctypes.POINTER(pcap_t), ctypes.c_int]
_pcap_setmintocopy.restype = ctypes.c_int

_pcap_close = dll.pcap_close
_pcap_close.argtypes = [ctypes.POINTER(pcap_t)]
_pcap_close.restype = None

_pcap_next_ex = dll.pcap_next_ex
_pcap_next_ex.argtypes = [ctypes.POINTER(pcap_t), ctypes.POINTER(ctypes.POINTER(pcap_pkthdr)),
                          ctypes.POINTER(ctypes.POINTER(u_char))]
_pcap_next_ex.restype = ctypes.c_int

_pcap_sendpacket = dll.pcap_sendpacket
_pcap_sendpacket.argtypes = [ctypes.POINTER(pcap_t), ctypes.c_void_p, ctypes.c_int]
_pcap_sendpacket.restype = ctypes.c_int

_pcap_compile = dll.pcap_compile
_pcap_compile.argtypes = [ctypes.POINTER(pcap_t), ctypes.POINTER(bpf_program), c_string, ctypes.c_int, bpf_u_int32]
_pcap_compile.restype = ctypes.c_int

_pcap_setfilter = dll.pcap_setfilter
_pcap_setfilter.argtypes = [ctypes.POINTER(pcap_t), ctypes.POINTER(bpf_program)]
_pcap_setfilter.restype = ctypes.c_int

_pcap_findalldevs = dll.pcap_findalldevs
_pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(pcap_if)), c_string]
_pcap_findalldevs.restype = ctypes.c_int


class WinPcap:
    """
    Wrapper class for (a subset of) pcap. See e.g. https://www.winpcap.org/docs/docs_412/html/main.html for a more
    detailed documentation of the underlying functionality.
    """

    @staticmethod
    def pcap_get_all_devices():
        devices = ctypes.POINTER(pcap_if)()
        error_buffer = ctypes.create_string_buffer(256)
        ret_val = _pcap_findalldevs(devices, error_buffer)

        if ret_val == 0:
            return devices
        else:
            return None

    @staticmethod
    def pcap_open_live(device, to_ms, snaplen=0xffff, promisc=0):
        """
        Create a pcap object and start capturing.
        :param device: The network device to open.
        :type device: string
        :param to_ms: The read timeout in milliseconds (not supported by all platforms). A timeout of 0 corresponds (on
        supporting platforms) to no timeout, i.e. a read waits until enough packets have arrived.
        :type to_ms: int
        :param snaplen: The maximum number of bytes to capture. If a packet is longer than the snaplen, all bytes beyond
        the snaplen are discarded.
        :type snaplen: int
        :param promisc: Whether the interface should be put into promiscuous mode. Note: the interface may already be in
        promiscuous mode independent of this flag.
        :type promisc: int
        :return: To opened pcap object.
        :rtype: POINTER(pcap_t)
        """
        device_buffer = ctypes.create_string_buffer(device.encode("utf8"))
        error_buffer = ctypes.create_string_buffer(256)
        p = _pcap_open_live(device_buffer, snaplen, promisc, to_ms, error_buffer)

        # Check for potential errors
        error = bytes(bytearray(error_buffer)).strip(b"\x00")
        if error:
            raise OSError(error)

        return p

    @staticmethod
    def pcap_close(p):
        """
        Closes a given pcap object, closing all associated files and deallocation resources.
        :param p: The pcap object to close.
        :type p: POINTER(pcap_t)
        """
        _pcap_close(p)

    @staticmethod
    def pcap_setmintocopy(p, size):
        """
        Set minimum amount of data received in a single system call (unless the timeout expires).
        :param p: The pcap object.
        :type p: POINTER(pcap_t)
        :param size: The minimum amount of data.
        :type size: int
        :return: 0 on success, -1 on failure.
        :rtype: int
        """
        return _pcap_setmintocopy(p, size)

    @staticmethod
    def pcap_next_ex(p, pkt_header, pkt_data):
        """
        Read the next available packet from a given interface.
        :param p: The pcap object to read from.
        :type p: POINTER(pcap_t)
        :param pkt_header: The header of the captured packet. Filled by pcap_next_ex, only value if return value is 0.
        :type pkt_header: POINTER(pcap_pkthdr)
        :param pkt_data: The data of the captured packet. Filled by pcap_next_ex, only value if return value is 0.
        :type pkt_data: POINTER(ctypes.c_ubyte)
        :return: 1 on success, 0 on timeout, -1 on error, -2 on EOF (offline capture only)
        :rtype: int
        """
        return _pcap_next_ex(p, pkt_header, pkt_data)

    @staticmethod
    def pcap_sendpacket(p, buf, size=None):
        """
        Send a raw packet to the network.
        :param p: The pcap object used to send the packet.
        :type p: POINTER(pcap_t)
        :param buf: The data of the packet to send.
        :type buf: c_void_p
        :param size: The size of the packet to send (i.e. the size of buf).
        :type size: int
        :return: -1 on failure, 0 on success.
        :rtype: int
        """
        return _pcap_sendpacket(p, buf, size)

    @staticmethod
    def pcap_compile(p, fp, str, optimize=0, netmask=-1):
        """
        Compile he given packet filter into a bpf filter program.
        :param p: The pcap object.
        :type p: POINTER(pcap_t)
        :param fp: A reference to the bpf filter program, filled in by pcap_compile()
        :type fp: bpf_program
        :param str: The filter expression to compile.
        :type str: string
        :param optimize: Whether the resulting filter program should be optimized.
        :type optimize: int
        :param netmask: Only used to check for IPv4 broadcast addresses in the filter program. See official Pcap
        documentation for more information.
        :type netmask: uint32
        :return: -1 on error (0 on success?)
        :rtype: int
        """
        filter_buffer = ctypes.create_string_buffer(str.encode("utf8"))
        return _pcap_compile(p, fp, filter_buffer, optimize, netmask)

    @staticmethod
    def pcap_setfilter(p, fp):
        """
        Apply a bpf filter to the given capture.
        :param p: The pcap object to apply the filter to.
        :type p: POINTER(pcap_t)
        :param fp: The bpf filter program to apply.
        :type fp: bpf_program
        :return: -1 on failure, 0 on success.
        :rtype: int
        """
        return _pcap_setfilter(p, fp)
