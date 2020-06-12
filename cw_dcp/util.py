"""
Copyright (c) 2020 Codewerk GmbH, Karlsruhe.
All Rights Reserved.
"""

from socket import *
from sys import argv, exit, stdout, stderr
from struct import pack, unpack, calcsize
from collections import namedtuple, OrderedDict
import binascii

import time


def mac_to_hex(mac):
    return b''.join(binascii.unhexlify(num) for num in mac.split(':'))


def hex_to_mac(hex_mac_str):
    return ':'.join(format(num, '02x') for num in hex_mac_str)


def hex_to_ip(hex_ip_str):
    return '.'.join(str(octet) for octet in hex_ip_str)


def unpack_data_w_keywords(args, preamble, preamble_size, payload, payload_field_len, fields, offset):
    data = args[0]
    # unpack known-size fields
    unpacked = unpack(preamble, data[0:preamble_size])
    keywords = {}
    # handle payload
    if payload:
        if payload_field_len is not None:
            payload_size = unpacked[list(fields.keys()).index(payload_field_len)] + offset
            keywords["payload"] = data[preamble_size:preamble_size + payload_size]
        else:
            keywords["payload"] = data[preamble_size:]
    return unpacked, keywords


def create_bytestr(name, fields, options={}, payload=True, payload_field_len=None, offset=0):
    fields = OrderedDict(fields)
    preamble = ">" + "".join([(f[0] if isinstance(f, tuple) else f) for f in fields.values()])
    preamble_size = calcsize(preamble)

    attribute_keys = list(fields.keys())
    attribute_keys.append('payload')
    # Create a subclass with elements from 'attribute_keys' as attributes
    t = namedtuple(name, attribute_keys)

    class _Bytestr(t):

        def __new__(cls, *args, **kwargs):
            # unpack (parse packet)
            if len(args) == 1:
                unpacked, keywords = unpack_data_w_keywords(args, preamble, preamble_size, payload, payload_field_len, fields, offset)
                self = t.__new__(cls, *unpacked, **keywords)
            else:
                self = t.__new__(cls, *args, **kwargs)
            return self

        def __bytes__(self):
            packed = pack(preamble, *(getattr(self, key) for key in fields.keys()))
            if payload:
                packed += bytes(self.payload)
            return packed

        def __len__(self):
            s = preamble_size
            if payload:
                s += len(self.payload)
            return s

    for k, v in options.items():
        setattr(_Bytestr, k, v)

    return _Bytestr


