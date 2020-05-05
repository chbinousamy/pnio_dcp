import binascii
import random
import profinet_dcp.util as util


class MockReturn:

    testnetz = {'Testnetz': [{'family': -1, 'address': '00-50-56-AC-DD-2E', 'netmask': None, 'broadcast': None, 'ptp': None},
                             {'family': 2, 'address': '10.0.2.124', 'netmask': '255.255.240.0', 'broadcast': None, 'ptp': None}]}
    src = b'005056acdd2e'
    dst = [b'000c296647a5', b'000e8ce53c58', b'00e07cc87258', b'40ecf804bf5e', b'40ecf803b7df']
    ident_resp = b'8892feff0501070100520000005402050004000002070201001000005343414c414e434520582d3230300202000800006e616d652d31020300060000002a0a01020400040000010002070004000000010102000e00010a00001efffff0000a000001'
    get_ip_resp = b'8892fefd0301070100520000001a0102000e00010a00001efffff0000a00000105040003000001000000000000000000'
    get_name_resp = b'8892fefd030107010052000000140202000800006e616d652d3105040003000001004345000000000000000000000000'
    set_err_code = [b'00', b'01', b'02', b'03', b'04', b'05', b'06']
    set_resp = b'8892fefd04010701005200000008050400030102'
    dst_custom = '01:0e:cf:00:00:00'

    def identify_response(self, key):
        dst_custom_hex = binascii.hexlify(util.s2mac(self.dst_custom))
        returns = {'IDENTIFY_ALL': [binascii.unhexlify(self.src + mac + self.ident_resp) for mac in self.dst],
                   'IDENTIFY': [binascii.unhexlify(self.src + dst_custom_hex + self.ident_resp)],
                   'SET_IP': [binascii.unhexlify(self.src + dst_custom_hex + self.set_resp + random.choice(self.set_err_code))],
                   'SET_NAME': [binascii.unhexlify(self.src + dst_custom_hex + self.set_resp + random.choice(self.set_err_code))],
                   'GET_IP': [binascii.unhexlify(self.src + dst_custom_hex + self.get_ip_resp)],
                   'GET_NAME': [binascii.unhexlify(self.src + dst_custom_hex + self.get_name_resp)]}
        return returns[key]
