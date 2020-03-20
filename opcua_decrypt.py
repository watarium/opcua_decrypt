from opcua.crypto import security_policies, uacrypto
from scapy.all import *

# pk = uacrypto.load_private_key('uaexpert_key.pem')
pk = uacrypto.load_private_key('uaserver.pem')
dcry = security_policies.DecryptorRsa(pk, uacrypto.decrypt_rsa_oaep, 42)
cl_dec_rsa = security_policies.DecryptorRsa(pk, uacrypto.decrypt_rsa15, 11)

packet_list = rdpcap('temp.pcapng')
raw_list = []

for packet_list_n in range(len(packet_list)):
    if 'Raw' in packet_list[packet_list_n]:
        raw_list.append(packet_list[packet_list_n][Raw].load)

for raw_list_n in range(len(raw_list)):
    try:
        target = raw_list[raw_list_n] + raw_list[raw_list_n + 1]
        enc = target[-512:]
        print('-----------')
        x = dcry.decrypt(enc)
        # print(enc)
        print(x)
        print('+++++++++++')
        print(x.decode())
    except ValueError:
        pass
    except TypeError:
        pass
    except IndexError:
        pass

