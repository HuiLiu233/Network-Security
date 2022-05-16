import hashlib
import os
from TextbookRSA import RSA
import logging
from CCA2 import Client, Server, Attacker


class OEAP_RSA:
    def __init__(self, RSA, OEAP_k0: int, OEAP_k1: int) -> None:
        self.k0 = OEAP_k0
        self.k1 = OEAP_k1
        self.rsa = RSA
        self.n, self.e, self.d = self.rsa.n, self.rsa.e, self.rsa.d
        self.pubkey = (self.rsa.n, self.rsa.e)
        self.RSA_BITS = self.rsa.RSA_BITS

    # return bytes a xor bytes b
    def bytesXor(self, a: bytes, b:bytes) -> bytes:
        assert(len(a) == len(b))
        result = bytearray()
        for b1, b2 in zip(a, b):
            result.append(b1 ^ b2)
        return bytes(result)

    # OEAP enocde bytes
    def encode(self, msg: bytes) -> bytes:
        # random r
        r = os.urandom(self.k0)
        # get m + k1 bytes G(r)
        G = hashlib.shake_256()
        G.update(r)
        G_r = G.digest(len(msg) + self.k1)

        # X = (msg + k1) xor G(r), (k1 is '\x00')
        X = self.bytesXor(msg + b'\x00' * self.k1, G_r)

        # get k0 bytes H(X)
        H = hashlib.shake_256()
        H.update(X)
        H_X = H.digest(self.k0)

        # Y = r xor H(X)
        Y = self.bytesXor(r, H_X)
        return X+Y

    # OEAP decode bytes
    def decode(self, oeap_msg: bytes) -> bytes:
        n = len(oeap_msg)
        # get X, Y
        X, Y = oeap_msg[ :n-self.k0], oeap_msg[n-self.k0: ]
        # get H(X)
        H = hashlib.shake_256()
        H.update(X)
        H_X = H.digest(self.k0)

        # r = Y xor H(X)
        r = self.bytesXor(Y, H_X)

        # get G(r)
        G = hashlib.shake_256()
        G.update(r)
        G_r = G.digest(n - self.k0)

        # msg = X xor G(r) - k1
        msg = self.bytesXor(X, G_r)[ :n-self.k0-self.k1]

        return msg, r

    # OEAP_RSA encrypt bytes
    def encrypt(self, textbytes: bytes) -> bytes: 
        # will be encode to RSA_BITS // 8 - 1 bytes.
        msg_block_size = self.RSA_BITS // 8 - self.k0 - self.k1 - 1
        start = 0
        encrypt_bytes = b""
        while start < len(textbytes):
            # encode msg_block to OEAP_block, len(OEAP) = RSA_BITS // 8 - 1 as in RSA
            # last block which is smaller than block_size
            if start + msg_block_size >= len(textbytes):
                OEAP_block = self.encode(textbytes[start:])
            else:
                OEAP_block = self.encode(textbytes[start: start + msg_block_size])

            encrypt_bytes += self.rsa.encrypt_block(OEAP_block)
            start += msg_block_size
        return encrypt_bytes

    # OEAP_RSA decrypt bytes
    def decrypt(self, ciphertext: bytes) -> bytes:
        # divide ciphertext into blocks to encrypt
        block_size = self.RSA_BITS // 8
        start = 0
        decode_bytes = b""
        while start < len(ciphertext):
            # last block which is smaller than block_size
            if start + block_size >= len(ciphertext):
                decrypt_bytes = self.rsa.decrypt_block(ciphertext[start: ])
            else:
                decrypt_bytes = self.rsa.decrypt_block(ciphertext[start: start + block_size])
            decode_bytes += self.decode(decrypt_bytes)[0]
            start += block_size
        return decode_bytes

    def get_r(self, ciphertext:bytes):
        # divide ciphertext into blocks to encrypt
        block_size = self.RSA_BITS // 8
        start = 0
        decode_bytes = b""
        r = b""
        while start < len(ciphertext):
            # last block which is smaller than block_size
            if start + block_size >= len(ciphertext):
                decrypt_bytes = self.rsa.decrypt_block(ciphertext[start: ])
            else:
                decrypt_bytes = self.rsa.decrypt_block(ciphertext[start: start + block_size])
            decode_bytes += self.decode(decrypt_bytes)[0]
            r += self.decode(decode_bytes)[1]
            start += block_size
        return r


    def write_task3(self, file_names, plaintext):
        cipher = self.encrypt(plaintext)
        dec = self.decrypt(cipher)
        r = self.get_r(cipher)

        # log the information
        with open(file_names['r'], 'w') as f: f.write(str(r.hex()))
        with open(file_names['padding_message'], 'w') as f: f.write(str(dec.hex()))
        with open(file_names['cipher'], 'w') as f: f.write(str(cipher.hex()))

def task3():
    file_names = {
        'p': 'Task1/RSA_p.txt',
        'q': 'Task1/RSA_q.txt',
        'n': 'Task1/RSA_Moduler.txt',
        'pk': 'Task1/RSA_Public_Key.txt',
        'sk': 'Task1/RSA_Secret_Key.txt',
        'cipher': 'Task1/Encrpted_Message.txt',
        'raw': 'Task1/Raw_Message.txt'
    }
    mechanism = RSA()
    plaintext = "test test test test test test test test test test test test test test test test test test test test test test test test test test test"
    mechanism.write_task1(file_names, plaintext)
    
    # Task 3
    files = {
        "r": 'Task3/Random_Number.txt',
        'padding_message': 'Task3/Message_After_Padding.txt',
        'cipher': 'Task3/Encrypted_Message.txt',
    }
    plaintext = b"test test test test test test test test test test test test test test test test test test test test test test test test test test test"
    mechanism = OEAP_RSA(mechanism, OEAP_k0= 6, OEAP_k1= 3)
    mechanism.write_task3(files, plaintext)


if __name__ == "__main__":
    task3()
    # logging.basicConfig(filename='log3.log', level=logging.DEBUG)
    # logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # wup_request = "hello".encode("utf-8")

    # # c-s init
    # OEAP = OEAP_RSA(RSA(), OEAP_k0= 6, OEAP_k1= 3)
    # client = Client()
    # server = Server(RSA= OEAP, wup_format = wup_request)
    
    # # C-S channel
    # pk = server.send_pk()
    # RSA_en_session_key = OEAP.encrypt(client.session_key)


    # # CCA2 ATTACK
    # attacker = Attacker(wup_request)
    # attacker.CCA2(server, pk, RSA_en_session_key)

