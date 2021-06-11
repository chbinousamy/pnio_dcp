"""
Copyright (c) 2021 Codewerk GmbH, Karlsruhe.
All Rights Reserved.
License: MIT License see LICENSE.md in the pnio_dcp root directory.
"""
import sys
from .l2socket import L2PcapSocket

if sys.platform == 'win32':
    L2Socket = L2PcapSocket
elif sys.platform.startswith('linux'):
    raise NotImplementedError(f"Platform {sys.platform} is currently not supported.")
else:
    raise NotImplementedError(f"Platform {sys.platform} is currently not supported.")
