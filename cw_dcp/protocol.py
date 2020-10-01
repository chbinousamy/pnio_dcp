"""
Copyright (c) 2020 Codewerk GmbH, Karlsruhe.
All Rights Reserved.
"""
from .util import create_bytestr, hex_to_mac

eth_header = create_bytestr("eth_header", (
        ("destination",  ("6s", hex_to_mac)),
        ("source",  ("6s", hex_to_mac)),
        ("type", ("H", "0x%04X"))
))

dcp_header = create_bytestr("dcp_header", (
    ("frame_id",     ("H", "0x%04X")),
    ("service_id",   "B"),
    ("service_type", "B"),
    ("xid",          ("I", "0x%08X")),
    ("resp",         "H"),
    ("len",       "H")
), options={
    "ETHER_TYPE": 0x8892,
    "GET": 3,
    "SET": 4,
    "IDENTIFY": 5,
    "REQUEST": 0,
    "RESPONSE": 1
})

DCPBlockRequest = create_bytestr("DCPBlockRequest", (
    ("opt",    "B"),
    ("subopt", "B"),
    ("len",    "H")
), payload_field_len="len")


class DCPBlock(create_bytestr("DCPBlockRequest", (
    ("opt",    "B"),
    ("subopt", "B"),
    ("len",    "H"),
    ("status",    "H"),
), payload_field_len="len", offset=-2)):

    IP_ADDRESS = (1, 2)
    DEVICE_FAMILY = (2, 1)
    NAME_OF_STATION = (2, 2)
    DEVICE_ID = (2, 3)
    RESET_TO_FACTORY = (5, 6)
    ALL = (0xFF, 0xFF)




