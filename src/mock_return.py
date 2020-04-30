import binascii
import random


class MockReturn:

    testnetz = {'Testnetz': [{'family': -1, 'address': '00-50-56-AC-DD-2E', 'netmask': None, 'broadcast': None, 'ptp': None},
                             {'family': 2, 'address': '10.0.2.124', 'netmask': '255.255.240.0', 'broadcast': None, 'ptp': None}]}
    src = b'005056acdd2e'
    dst = [b'000c296647a5', b'000e8ce53c58', b'00e07cc87258', b'40ecf804bf5e', b'40ecf803b7df']
    ident_resp = b'8892feff0501070100520000005402050004000002070201001000005343414c414e434520582d3230300202000800006e616d652d31020300060000002a0a01020400040000010002070004000000010102000e00010a00001efffff0000a000001'
    get_ip_resp = b'8892fefd0301070100520000001a0102000e00010a00001efffff0000a00000105040003000001000000000000000000'
    get_name_resp = b'8892fefd030107010052000000140202000800006e616d652d3105040003000001004345000000000000000000000000'
    # set_err_code = [b'00', b'01', b'02', b'03', b'04', b'05', b'06']
    set_err_code = [b'01', b'02', b'03', b'04', b'05', b'06']
    set_resp = b'8892fefd04010701005200000008050400030102'

    def identify_response(self, data):
        data_hex = binascii.hexlify(data)
        service = data[16]
        option = data_hex[52:56]
        if service == 5:
            if data_hex[0:12] == b'010ecf000000':
                ret_value = [binascii.unhexlify(self.src + mac + self.ident_resp) for mac in self.dst]
            else:
                ret_value = [binascii.unhexlify(self.src + data_hex[0:12] + self.ident_resp)]
        elif service == 4:
            if option == b'0102':
                ret_value = [binascii.unhexlify(self.src + data_hex[0:12] + self.set_resp + random.choice(self.set_err_code))]
            elif option == b'0202':
                ret_value = [binascii.unhexlify(self.src + data_hex[0:12] + self.set_resp + random.choice(self.set_err_code))]
        elif service == 3:
            if option == b'0102':
                ret_value = [binascii.unhexlify(self.src + data_hex[0:12] + self.get_ip_resp)]
            elif option == b'0202':
                ret_value = [binascii.unhexlify(self.src + data_hex[0:12] + self.get_name_resp)]

        return ret_value
