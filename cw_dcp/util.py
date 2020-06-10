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


class TimeoutLimit:
    def __init__(self, seconds):
        self.timeout = time.time() + seconds
        self.timed_out = time.time() > self.timeout


def create_bytestr(name, fields, options={}, payload=True, payload_field_len=None, offset=0):
    fields = OrderedDict(fields)
    preamble = ">" + "".join([(f[0] if isinstance(f, tuple) else f) for f in fields.values()])
    preamble_size = calcsize(preamble)

    names_keys_tuple = list(fields.keys())
    if payload:
        names_keys_tuple.append("payload")

    t = namedtuple(name, names_keys_tuple)

    class _Bytestr(t):

        def __new__(cls, *args, **kwargs):

            # unpack (parse packet)
            if len(args) == 1:
                data = args[0]

                # unpack known-size fields
                unpacked = unpack(preamble, data[0:preamble_size])

                kw = {}
                # handle payload
                if payload:
                    if payload_field_len is not None:
                        payload_size = unpacked[list(fields.keys()).index(payload_field_len)] + offset
                        kw["payload"] = data[preamble_size:preamble_size + payload_size]
                    else:
                        kw["payload"] = data[preamble_size:]

                # finally create instance
                self = t.__new__(cls, *unpacked, **kw)

            # pack (create packet)
            else:
                self = t.__new__(cls, *args, **kwargs)

            return self

        def __str__(self):
            ret = "%s packet (%d bytes)\n" % (name, len(self))
            for k, v in fields.items():
                ret += k + ": "
                value = getattr(self, k)
                if isinstance(v, tuple):
                    if isinstance(v[1], str):
                        ret += v[1] % value
                    else:
                        ret += v[1](value)
                else:
                    ret += str(value)
                ret += "\n"
            return ret

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

    _Bytestr.fmt = preamble
    _Bytestr.fmt_size = preamble

    for k, v in options.items():
        setattr(_Bytestr, k, v)

    return _Bytestr


