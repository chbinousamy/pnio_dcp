import time
import pytest
import psutil
import logging
import socket

from pnio_dcp.l2socket.l2socket import L2PcapSocket
from mock_return import MockReturn


@pytest.fixture(scope='function')
def l2_socket():
    ip = TestPcapSocket.get_ip()
    l2_socket = L2PcapSocket(ip)
    yield l2_socket
    l2_socket.close()


class TestPcapSocket:
    timeout = 10

    @staticmethod
    def get_ip(address_family=socket.AF_INET):
        addrs = psutil.net_if_addrs()
        for iface_name, config in addrs.items():
            for address in config:
                if address.family == address_family and address.address != '127.0.0.1':
                    logging.info(f"Using ip {address.address} for socket tests.")
                    return address.address
        logging.warning("Could not find valid ip address with psutil.net_if_addrs()")

    def test_open_close_ipv4(self):
        ip = TestPcapSocket.get_ip()

        l2_socket = L2PcapSocket(ip)
        l2_socket.close()

    def test_open_close_ipv6(self):
        ip = TestPcapSocket.get_ip(socket.AF_INET6)
        print(ip)

        l2_socket = L2PcapSocket(ip)
        l2_socket.close()

    def test_send(self, l2_socket):
        data = bytes([0] * 64)
        l2_socket.send(data)

    def test_recv(self, l2_socket):
        l2_socket.recv()

    def test_send_recv(self, l2_socket):
        data = bytes([0] * 64)
        l2_socket.send(data)

        start = time.time()
        packet_count = 0
        received_sent_data = False

        while time.time() < start + self.timeout:
            received = l2_socket.recv()
            if received is not None:
                packet_count += 1
            if received == data:
                received_sent_data = True
                break
        end = time.time()

        logging.info(f"Sent data {'received' if received_sent_data else 'not received'} after {packet_count} packets "
                     f"and {end - start} s")
        assert received_sent_data

    def test_filter(self):
        mock_return = MockReturn()
        mock_return.dst_custom = mock_return.dst[0]

        ip = TestPcapSocket.get_ip()
        filter = f"ether host {mock_return.src} and ether proto {mock_return.eth_type}"
        valid_data = mock_return.identify_response('IDENTIFY')[0]
        invalid_data = bytes([0] * 64)

        l2_socket = L2PcapSocket(ip, filter)
        l2_socket.send(valid_data)

        end = time.time() + self.timeout
        received_valid_data = False

        while time.time() < end:
            received = l2_socket.recv()
            assert received != invalid_data
            if received == valid_data:
                received_valid_data = True

        assert received_valid_data

        l2_socket.close()
