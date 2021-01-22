import setuptools_scm

__version__ = setuptools_scm.get_version(root='..', relative_to=__file__)

from .protocol import eth_header, dcp_header, DCPBlockRequest, DCPBlock
from .util import mac_to_hex, hex_to_mac, hex_to_ip
from .pnio_dcp import DCP, Device
from .error import DcpError, DcpTimeoutError
