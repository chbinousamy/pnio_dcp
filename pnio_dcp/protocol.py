"""
Copyright (c) 2020 Codewerk GmbH, Karlsruhe.
All Rights Reserved.
License: MIT License see LICENSE.md in the pnio_dcp root directory.
"""
import struct
from pnio_dcp import util


class HeaderField:
    """Used to describe a header field in a packet header."""

    def __init__(self, name, format, default_value=None, pack_function=None, unpack_function=None):
        """
        Defines a field in a packet header. At least a name and format must be provided. Optionally, a default value
        can be given or additional pack and unpack functions to apply before/after packing/unpacking a value.
        :param name: The name of the header field.
        :type name: string
        :param format: The struct format for values stored in this field.
        :type format: string
        :param default_value: A default value to use for this header field when no other value is given.
        :type default_value: Optional[Any]
        :param pack_function: An additional function applied to the field's value before packing.
        :type pack_function: Optional[Any -> Any]
        :param unpack_function: An additional function applied after unpacking a value. Should be inverse to
        pack_function. An example would be converting mac addresses to binary with the pack_function and revertig them
        to string with the unpack_function.
        :type unpack_function: Optional[Any -> Any]
        """
        self.name = name
        self.format = format
        self.default_value = default_value
        self.pack_function = pack_function
        self.unpack_function = unpack_function

    def pack(self, value):
        """
        Pack the given value using the pack_function (if defined).
        When the given value is None, the default value is used.
        :param value: The value to pack.
        :type value: Any
        :return: The packed value.
        :rtype: Any
        """
        if value is None:
            value = self.default_value
        if self.pack_function is not None:
            value = self.pack_function(value)
        return value

    def unpack(self, value):
        """
        Unpack the given value using the unpack_function (if defined).
        :param value: The packed value.
        :type value: Any
        :return: The unpacked value.
        :rtype: Any
        """
        if self.unpack_function is not None:
            value = self.unpack_function(value)
        return value


class Packet:

    # Defines all fields in the packet header in the correct order.
    # Each field is defined through a HeaderField object defined above.
    HEADER_FIELD_FORMATS = []

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

        self.unpack_payload(data)

    def unpack_payload(self, data):
        """
        Unpack the payload from the data after the header has already been unpacked.
        :param data: The whole packet as bytes.
        :type data: bytes
        """
        self.payload = data[self.header_length:]

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
        payload_length = len(bytes(self.payload))
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

    def __init__(self, opt=None, subopt=None, len=None, payload=None, data=None):
        self.opt = None
        self.subopt = None
        self.len = None
        if data:
            super().__init__(data=data)
        else:
            super().__init__(opt=opt, subopt=subopt, len=len, payload=payload)

    def unpack_payload(self, data):
        payload_end = self.header_length + self.len
        self.payload = data[self.header_length:payload_end]


class DCPBlock(Packet):
    HEADER_FIELD_FORMATS = [
        HeaderField("opt", "B"),
        HeaderField("subopt", "B"),
        HeaderField("len", "H"),
        HeaderField("status", "H"),
    ]

    def __init__(self, opt=None, subopt=None, len=None, status=None, payload=None, data=None):
        self.opt = None
        self.subopt = None
        self.len = None
        self.status = None
        if data:
            super().__init__(data=data)
        else:
            super().__init__(opt=opt, subopt=subopt, len=len, status=status, payload=payload)

    def unpack_payload(self, data):
        payload_end = self.header_length + self.len - 2
        self.payload = data[self.header_length:payload_end]
