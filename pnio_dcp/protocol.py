"""
Copyright (c) 2020 Codewerk GmbH, Karlsruhe.
All Rights Reserved.
License: MIT License see LICENSE.md in the pnio_dcp root directory.
"""
import struct
from pnio_dcp import util


class HeaderField:

    def __init__(self, name, format, default_value=None, pack_function=None, unpack_function=None):
        self.name = name
        self.format = format
        self.default_value = default_value
        self.pack_function = pack_function
        self.unpack_function = unpack_function

    def pack(self, value):
        if value is None:
            value = self.default_value
        if self.pack_function is not None:
            value = self.pack_function(value)
        return value

    def unpack(self, value):
        if self.unpack_function is not None:
            value = self.unpack_function(value)
        return value


class Packet:

    # Defines all fields in the packet header in the correct order.
    # Each field is defined through a HeaderField object defined above.
    HEADER_FIELD_FORMATS = []

    # The name of the header field containing the payload length (if applicable, ignored if None)
    PAYLOAD_LENGTH_FIELD = None
    # Additional payload length to be added onto the value provided by the payload length field (if applicable).
    # TODO is this really necessary?
    ADDITIONAL_PAYLOAD_LENGTH = 0

    # Whether this type of packet can contain a payload
    HAS_PAYLOAD = True

    def __init__(self, data=None, payload=None, **kwargs):
        """
        Create a new packet. If data is given, the packets is initialized by unpacking the data. Otherwise, the payload
        and header fields are initialized from the remaining arguments.
        :param data: A packed packet es expected by unpack.
        :type data: bytes
        :param payload: The payload of the packet.
        :type payload: Any
        :param kwargs: Can be used to initialize the header fields defined in HEADER_FIELD_FORMATS
        :type kwargs: Any
        """
        self.header_format = ">" + "".join([field.format for field in self.HEADER_FIELD_FORMATS])
        self.header_length = struct.calcsize(self.header_format)

        self.payload = 0

        if data:
            self.unpack(data)
        else:
            valid_header_fields = [field.name for field in self.HEADER_FIELD_FORMATS]
            invalid_kwargs = [name for name in kwargs.keys() if name not in valid_header_fields]
            if invalid_kwargs:
                pass  # TODO log warning

            for name, value in kwargs.items():
                if name in valid_header_fields:
                    setattr(self, name, value)

            if payload:
                self.payload = payload

    def unpack(self, data):
        """
        Unpack the packet from the given data.
        :param data: The packet packed to a bytes object i.e. by Packet.pack()
        :type data: bytes
        """
        unpacked_header = struct.unpack(self.header_format, data[:self.header_length])
        for field, value in zip(self.HEADER_FIELD_FORMATS, unpacked_header):
            setattr(self, field.name, field.unpack(value))

        if self.HAS_PAYLOAD:
            payload_end = None
            if self.PAYLOAD_LENGTH_FIELD:
                payload_length = getattr(self, self.PAYLOAD_LENGTH_FIELD) + self.ADDITIONAL_PAYLOAD_LENGTH
                payload_end = self.header_length + payload_length
            self.payload = data[self.header_length:payload_end]

    def pack(self):
        """
        Pack this packet into a bytes object containing the header and the optional payload.
        The header fields are packed according to the format defined by 'preamble'.
        If there is a payload, it is converted to bytes and appended to the packed fields.
        :return: This packet converted to a bytes object.
        :rtype: bytes
        """
        ordered_header_fields = [field.pack(getattr(self, field.name, None))
                                 for field in self.HEADER_FIELD_FORMATS]
        packed = struct.pack(self.header_format, *ordered_header_fields)
        if self.HAS_PAYLOAD:
            packed += bytes(self.payload)
        return packed

    def __bytes__(self):
        """
        Pack this packet into a bytes object using the pack function.
        :return: This packet as bytes object.
        :rtype: bytes
        """
        return self.pack()

    def __len__(self):
        """
        Compute and return the length of the packet.
        That is the size of the preamble + the length of the payload (if there is a payload).
        :return: The length of the packet.
        :rtype: int
        """
        payload_length = len(bytes(self.payload)) if self.HAS_PAYLOAD else 0
        return self.header_length + payload_length


class EthernetPacket(Packet):
    """An Ethernet packet consisting of destination and source mac address and an ether type."""
    HEADER_FIELD_FORMATS = [
        HeaderField("destination", "6s", None, util.mac_address_to_bytes, util.mac_address_to_string),
        HeaderField("source", "6s", None, util.mac_address_to_bytes, util.mac_address_to_string),
        HeaderField("type", "H"),
    ]

    def __init__(self, destination=None, source=None, type=None, payload=None, data=None):
        self.destination = None
        self.source = None
        self.type = None
        if data:
            super().__init__(data=data)
        else:
            super().__init__(destination=destination, source=source, type=type, payload=payload)


class DCPPacket(Packet):
    HEADER_FIELD_FORMATS = [
        HeaderField("frame_id", "H"),
        HeaderField("service_id", "B"),
        HeaderField("service_type", "B"),
        HeaderField("xid", "I"),
        HeaderField("resp", "H"),
        HeaderField("len", "H"),
    ]

    def __init__(self, frame_id=None, service_id=None, service_type=None, xid=None, resp=None, len=None, payload=None,
                 data=None):
        self.frame_id = None
        self.service_id = None
        self.service_type = None
        self.xid = None
        self.resp = None
        self.len = None
        if data:
            super().__init__(data=data)
        else:
            super().__init__(frame_id=frame_id, service_id=service_id, service_type=service_type, xid=xid, resp=resp,
                             len=len, payload=payload)


class DCPBlockRequest(Packet):
    HEADER_FIELD_FORMATS = [
        HeaderField("opt", "B"),
        HeaderField("subopt", "B"),
        HeaderField("len", "H"),
    ]

    PAYLOAD_LENGTH_FIELD = "len"

    def __init__(self, opt=None, subopt=None, len=None, payload=None, data=None):
        self.opt = None
        self.subopt = None
        self.len = None
        if data:
            super().__init__(data=data)
        else:
            super().__init__(opt=opt, subopt=subopt, len=len, payload=payload)


class DCPBlock(Packet):
    HEADER_FIELD_FORMATS = [
        HeaderField("opt", "B"),
        HeaderField("subopt", "B"),
        HeaderField("len", "H"),
        HeaderField("status", "H"),
    ]

    PAYLOAD_LENGTH_FIELD = "len"
    ADDITIONAL_PAYLOAD_LENGTH = -2

    def __init__(self, opt=None, subopt=None, len=None, status=None, payload=None, data=None):
        self.opt = None
        self.subopt = None
        self.len = None
        self.status = None
        if data:
            super().__init__(data=data)
        else:
            super().__init__(opt=opt, subopt=subopt, len=len, status=status, payload=payload)
