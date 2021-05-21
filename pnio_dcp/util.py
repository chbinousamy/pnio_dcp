"""
Copyright (c) 2020 Codewerk GmbH, Karlsruhe.
All Rights Reserved.
License: MIT License see LICENSE.md in the pnio_dcp root directory.
"""
import binascii


def mac_to_hex(mac):
    """
    Converts the mac address from ':'-separated strings to bytes by encoding each part as binary and concatenating them.
    :param mac: The mac address given as ':'-separated strings.
    :type mac: string
    :return: The mac address encoded as bytes.
    :rtype: bytes
    """
    return b''.join(binascii.unhexlify(num) for num in mac.split(':'))


def hex_to_mac(hex_mac_str):
    """
    Converts the mac address from bytes to ':'-separated strings by decoding each byte to a 2-digit lower-case string
    and concatenating them separated by ':'.
    :param hex_mac_str: The mac address encoded as bytes.
    :type hex_mac_str: bytes
    :return: The mac address as ':'-separated lower-case strings.
    :rtype: string
    """
    return ':'.join(format(num, '02x') for num in hex_mac_str)


def hex_to_ip(hex_ip_str):
    """
    Converts the ip address from bytes to string by decoding each byte to int and concatenating them separated by '.'.
    :param hex_ip_str: The ip address encoded as bytes.
    :type hex_ip_str: bytes
    :return: The ip address as string.
    :rtype: string
    """
    return '.'.join(str(octet) for octet in hex_ip_str)
