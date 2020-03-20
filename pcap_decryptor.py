from scapy.all import *
from opcua.crypto import security_policies, uacrypto

client_ip = '192.168.2.14'
server_ip = '192.168.2.10'
packet_list = rdpcap('pythonopcua.pcapng')
client_private_key = uacrypto.load_private_key('uaexpert_key.pem')
server_private_key = uacrypto.load_private_key('uaserver.pem')

# In case of you use Basic256Rsa256 as security policy
client_decriptor = security_policies.DecryptorRsa(client_private_key, uacrypto.decrypt_rsa_oaep, 42)
server_decriptor = security_policies.DecryptorRsa(server_private_key, uacrypto.decrypt_rsa_oaep, 42)

raw_list = []
dst_ip_list = []

def get_server_nonce(payload):
    data = payload[-512:]
    try:
        result = client_decriptor.decrypt(data)
        server_nonce = result[64:96]
        print('server_nance: '+ str(server_nonce))
        return server_nonce
    except ValueError:
        pass

def get_client_nonce(payload):
    data = payload[-512:]
    try:
        result = server_decriptor.decrypt(data)
        client_nonce = result[57:89]
        print('client_nance: '+ str(client_nonce))
        return client_nonce
    except ValueError:
        pass

def get_nonce():
    client_nonce = None
    server_nonce = None

    for packet_list_n in range(len(packet_list)):
        if 'Raw' in packet_list[packet_list_n]:
            dst_ip_list.append(packet_list[packet_list_n]['IP'].dst)
            raw_list.append(packet_list[packet_list_n][Raw].load)

    for raw_list_n in range(len(raw_list)):
        try:
            if raw_list[raw_list_n][:4] == b'OPNF' and raw_list[raw_list_n][59:73] == b'Basic256Sha256':
                if dst_ip_list[raw_list_n] == server_ip:
                    payload = raw_list[raw_list_n] + raw_list[raw_list_n + 1]
                    client_nonce = get_client_nonce(payload)
                if dst_ip_list[raw_list_n] == client_ip:
                    payload = raw_list[raw_list_n] + raw_list[raw_list_n + 1]
                    server_nonce = get_server_nonce(payload)
                if client_nonce and server_nonce is not None:
                        return client_nonce, server_nonce
        except ValueError:
            pass
        except TypeError:
            pass
        except IndexError:
            pass

def make_keys(client_nonce, server_nonce):
    key_sizes = (32, 32, 16)

    # refer self.security_policy.make_local_symmetric_key(self.remote_nonce, self.local_nonce) from security_policies.py
    (sigkey, key, init_vec) = uacrypto.p_sha256(server_nonce, client_nonce, key_sizes)
    server_decrypt_aes = security_policies.DecryptorAesCbc(key, init_vec)
    client_encrypt_aes = security_policies.EncryptorAesCbc(key, init_vec)
    client_sign_aes = security_policies.SignerAesCbc(sigkey)

    # refer self.security_policy.make_remote_symmetric_key(self.local_nonce, self.remote_nonce) from security_policies.py
    (sigkey, key, init_vec) = uacrypto.p_sha256(client_nonce, server_nonce, key_sizes)
    client_decrypt_aes = security_policies.DecryptorAesCbc(key, init_vec)
    server_encrypt_aes = security_policies.EncryptorAesCbc(key, init_vec)
    server_sign_aes = security_policies.SignerAesCbc(sigkey)

    return server_decrypt_aes, client_encrypt_aes, client_sign_aes, client_decrypt_aes, server_encrypt_aes, server_sign_aes

def decrypt(client_decrypt_aes, server_decrypt_aes):
    for raw_list_n in range(len(raw_list)):
        try:
            if raw_list[raw_list_n][:4] == b'MSGF':
                # if dst_ip_list[raw_list_n] == client_ip:
                #     payload = raw_list[raw_list_n]
                #     decrypted = client_decrypt_aes.decrypt(payload)
                #     print(decrypted)

                if dst_ip_list[raw_list_n] == server_ip:
                    payload = raw_list[raw_list_n]
                    decrypted = server_decrypt_aes.decrypt(payload)
                    utf8decrypted = decrypted.decode('utf-8', errors='ignore')
                    if 'MyVariable' in utf8decrypted:
                        unpack_data = struct.unpack('<d', decrypted[140:148])[0]
                        return unpack_data

        except ValueError as e:
            pass

if len(packet_list) > 4:
    client_nonce, server_nonce = get_nonce()
    server_decrypt_aes, client_encrypt_aes, client_sign_aes, client_decrypt_aes, server_encrypt_aes, server_sign_aes = make_keys(client_nonce, server_nonce)
    unpack_data = decrypt(client_decrypt_aes, server_decrypt_aes)
    print('MyVariable = ' + str(unpack_data))