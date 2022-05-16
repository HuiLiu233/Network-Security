import RandPrime
import math


class RSA_Client:
    def  __init__(self, pk, RSA_BITS=1024, false_positive_prob=1e-6) -> None:
        self.RSA_BITS, self.false_positive_prob = RSA_BITS, false_positive_prob
        self.n, self.e = pk[0], pk[1]
    
    def encrypt_block(self, block: bytes) -> bytes:
        block_int = int.from_bytes(block, byteorder = "big")  
        encrypt_block = pow(block_int, self.e, self.n)         

        # recover the block size to RSA_BITS // 8
        # not the last block, pad to RSA_BITS // 8
        if len(block) == self.RSA_BITS // 8 - 1:
            return encrypt_block.to_bytes(self.RSA_BITS // 8, byteorder = 'big')
        # last block, no need to pad
        return encrypt_block.to_bytes((encrypt_block.bit_length() + 7)//8, byteorder = 'big')
        
    # encrypt bytes plaintext into bytes ciphertext.   
    def encrypt(self, textbytes: bytes) -> bytes:
        # divide textbytes into blocks to encrypt
        # CAN NOT BE RSA_BITS // 8. WHICH MAY LARGER THAN N
        block_size = self.RSA_BITS // 8 - 1
        start = 0
        encrypt_bytes = b""
        while start < len(textbytes):
            # last block which is smaller than block_size
            if start + block_size >= len(textbytes):
                encrypt_bytes += self.encrypt_block(textbytes[start: ])
            else :
                encrypt_bytes += self.encrypt_block(textbytes[start: start + block_size])
            start += block_size
        return encrypt_bytes



class RSA:
    def __init__(self, RSA_BITS=1024, false_positive_prob=1e-6) -> None:
        # RSA_BITS: security parameters, fp_prob: fp of Rabin Miller test
        # random prime is half the key length long.
        self.RSA_BITS, self.false_positive_prob = RSA_BITS, false_positive_prob
        self.p, self.q = self.generate_key_pair()

    # refresh and generate pk, sk
    def generate_key_pair(self):
        # random prime is half the key length long.
        prime_p = RandPrime.getPrime(self.RSA_BITS//2, self.false_positive_prob)
        prime_q = RandPrime.getPrime(self.RSA_BITS//2, self.false_positive_prob)
        n = prime_p * prime_q
        phi_n = (prime_p - 1) * (prime_q - 1)
        self.e = None

        # generate e from sieve_base
        # 10000 prime numbers are in sieve_base. 
        # Their product must biger than 10**50000, which is big enought to find e.
        for p in RandPrime.sieve_base:
            if ( p < phi_n and math.gcd(p, phi_n) == 1):
                self.e = p
                break
        if not self.e:
            raise ValueError("Exponent `e` generation failed. Try shorter key length.")
        
        # use exgcd to generte d s.t. e * d mod(phi_i) == 1 (since gcd(e, phi_i) is 1)
        d = RandPrime.exgcd(self.e, phi_n) % phi_n
        self.n = n
        self.d = d
        return prime_p, prime_q

    # encrypt single byte block.
    def encrypt_block(self, block: bytes) -> bytes:
        block_int = int.from_bytes(block, byteorder = "big")  
        # encrypt_block = block_int ** e mod(n)
        encrypt_block = pow(block_int, self.e, self.n)         

        # recover the block size to RSA_BITS // 8
        # not the last block, pad to RSA_BITS // 8
        if len(block) == self.RSA_BITS // 8 - 1:
            return encrypt_block.to_bytes(self.RSA_BITS // 8, byteorder = 'big')
        # last block, no need to pad
        return encrypt_block.to_bytes((encrypt_block.bit_length() + 7)//8, byteorder = 'big')
        
    # encrypt bytes plaintext into bytes ciphertext.   
    def encrypt(self, textbytes: bytes) -> bytes:
        # divide textbytes into blocks to encrypt
        # CAN NOT BE RSA_BITS // 8. WHICH MAY LARGER THAN N
        block_size = self.RSA_BITS // 8 - 1
        start = 0
        encrypt_bytes = b""
        while start < len(textbytes):
            # last block which is smaller than block_size
            if start + block_size >= len(textbytes):
                encrypt_bytes += self.encrypt_block(textbytes[start: ])
            else :
                encrypt_bytes += self.encrypt_block(textbytes[start: start + block_size])
            start += block_size
        return encrypt_bytes

    # decrypt single byte block.
    def decrypt_block(self, block: bytes) -> bytes:
        block_int = int.from_bytes(block, byteorder = "big")

        # decrypt_block = block_int ** d mod(n)
        decrypt_block = pow(block_int, self.d, self.n)

        # recover the block size to ceil(decrypt_block.bit_length() / 8)
        return decrypt_block.to_bytes((decrypt_block.bit_length() + 7)//8, byteorder = 'big')

    # decrypt bytes ciphertext into bytes plaintext.   
    def decrypt(self, ciphertext: bytes) -> bytes:
        # divide ciphertext into blocks to encrypt
        start = 0
        block_size = self.RSA_BITS // 8
        decrypt_bytes = b""
        while start < len(ciphertext):

            # last block which is smaller than block_size
            if start + block_size > len(ciphertext):
                decrypt_bytes += self.decrypt_block(ciphertext[start: ])
            else :
                decrypt_bytes += self.decrypt_block(ciphertext[start: start + block_size])

            start += block_size
        return decrypt_bytes

    # pring random p, q, pubkey, selfkey
    def showme(self) -> None:
        for item, value in zip(
            ["random prime p: ", "random prime q: ", "pubkey: ", "selfkey: ", "e: ", "d: "],
            [self.prime_p, self.prime_q, self.pubkey, self.selfkey, self.e, self.d]):
            print(f"{item:25}{value}")
    
    def write_task1(self, file_names, plaintext):
        # p, q = self.generate_key_pair()
        # encrpt and decrpt
        cipher = self.encrypt(plaintext.encode("utf-8"))
        dec = self.decrypt(cipher).decode("utf-8")
        print(cipher)
        print(dec)
        print(dec == plaintext)
        # log the information
        with open(file_names['p'], 'w') as f: f.write(str(self.p))
        with open(file_names['q'], 'w') as f: f.write(str(self.q))
        with open(file_names['n'], 'w') as f: f.write(str(self.n))
        with open(file_names['pk'], 'w') as f: 
            f.writelines([str(self.n), str(self.e)])
        with open(file_names['sk'], 'w') as f:
            f.writelines([str(self.n), str(self.d)])
        with open(file_names['cipher'], 'w') as f: f.write(str(cipher.hex()))
        with open(file_names['raw'], 'w') as f: f.write(str(plaintext))


if __name__ == "__main__":
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
    plaintext = """Plaintext is what encryption algorithms, or ciphers, transform an encrypted message into. It is any readable data — including binary files — in a form that can be seen or utilized without the need for a decryption key or decryption device.
    Plaintext would refer to any message, document, file, and the like intended or having been encrypted. Plaintext is the input to a crypto system, with ciphertext being the output. In cryptography, algorithms transform plaintext into ciphertext, and ciphertext into plaintext. These respective processes are called encryption and decryption. The basis for using such a system is to ensure that the data can only be read by its intended recipient.
Securing plaintext stored in a computer file is paramount, as its unsanctioned theft, disclosure, or transmission results in its contents being fully disclosed and thus potentially actionable. If stored, then, the storage media, the device, its components, and all backups must be secured.
It's standard operating procedure encrypt sensitive data before it is stored or transmitted rather than store or communicate it as plaintext. Data owners or custodians have come to accept that the systems inside which plaintext is stored, and the communications channels over which it travels, are insecure. It is therefore better to handle the data itself with care just as the systems themselves are secured."""
    mechanism.write_task1(file_names, plaintext)