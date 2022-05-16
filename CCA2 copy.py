import os
from TextbookRSA import RSA, RSA_Client
from Crypto.Cipher import AES
import logging
from RandPrime import AESUnpad, AESPad

class Server:
    # initiate RSA and send public key to client
    def __init__(self, RSA, wup_format:bytes, AES_BITS=128) -> None:
        # get RSA and save pubkey
        self.RSA = RSA
        self.wup_format = wup_format
        self.session_key = None
        self.AES_session_key = None
        self.AES_BITS = 128
        
        
        logger.info(f"""\n\n\n ###[SERVER]: Initiated. ###
        \t RSA Public Key: \n\t\tn: {self.RSA.n}\n\t\te:{self.RSA.e}
        \t RSA Secrete Key: \n\t\tn: {self.RSA.n}\n\t\td:{self.RSA.d}""")
    
    # send public key
    def send_pk(self):
        pk = [self.RSA.n, self.RSA.e]
        logger.info(f"""\n\n\n ###[SERVER]: Send Public RSA Key. ###
        \t RSA Public Key: \n\t\tn: {pk[0]}\n\t\te:{pk[1]}""")
        return pk

    # get RSA encrypted session key, decrpt it
    def getSessionKey(self, RSA_en_session_key:bytes) -> None:
        # RSA decrypt session key, get last 128 bit as session key
        RSA_de_session_key = self.RSA.decrypt(RSA_en_session_key)
        self.session_key = RSA_de_session_key[-self.AES_BITS//8:]
        # generate AES session key using session key
        self.AES_session_key = AES.new(self.session_key, AES.MODE_ECB)

        # log the session key
        if self.session_key:
            logger.info(f"""\n\n\n ###[SERVER]: RSA Encrypted Session Key Received. ###
            \tRSA Encrypted Session Key: {RSA_en_session_key}
            \tSession Key: {self.session_key}
            \tAES Session Key: {self.AES_session_key}""")


    # get AES encrypted wup request, decrpted it
    def getWup(self, AES_en_wup:bytes) -> bool:
        logger.info(f"""\n\n\n ###[SERVER]: AES Enrypted WUP Request Received. ###
        \t AES Encrypted WUP Request: {AES_en_wup}""")

        # use AES to decrypt wup and unpad it
        AES_de_wup = self.AES_session_key.decrypt(AES_en_wup)
        unpad_session_request = AESUnpad(AES_de_wup, self.AES_BITS)
        
        # if session request(wup) is the same format 
        if unpad_session_request == self.wup_format:
            logger.info(f"""\n\n\n ###[SERVER]: WUP REQUEST MATCH. ###
            \tWUP Request: {unpad_session_request}""")
            return True
        else:
            logger.info(f"""\n\n\n ###[SERVER]: WUP REQUEST UNMATCH. ###""")
        return False


class Client:
    def __init__(self, AES_BITS=128, logger=None) -> None:
        # client: create RSA(); create session_key.
        self.RSA_client = None
        self.AES_BITS= AES_BITS
        # create session key and AES session key
        self.session_key = os.urandom(self.AES_BITS//8)
        self.AES_session_key = AES.new(self.session_key, AES.MODE_ECB)
        logger.info(f"""\n\n\n ###[CLIENT]: Initiated. ###
        \tSession Key:{self.session_key}
        \tAES session key: {self.AES_session_key}""")

    # receive RSA pk, send RSA encrypted session key.
    def receive_RSA_pk(self, pk):
        logger.info(f"""\n\n\n ###[CLIENT]: RSA Public Key Received. ###
        \t RSA Public Key: \n\t\tn: {pk[0]}\n\t\te:{pk[1]}""")
        self.RSA_client = RSA_Client(pk)
        

        # encrypt session key using RSA
        self.RSA_en_session_key = self.RSA_client.encrypt(self.session_key)
        logger.info(f"""\n\n\n ###[CLIENT]: Send RSA Encrypted Session Key ###
        \t RSA Encrypted session key: {self.RSA_en_session_key}""")
        return self.RSA_en_session_key


    # send WUP request using AES session key
    def send_wup_request(self, wup_request):
        # encrypt WUP request 
        self.AES_en_wup = self.AES_session_key.encrypt(AESPad(wup_request, self.AES_BITS))
        logger.info(f"""\n\n\n ###[CLIENT]: Send AES Encrypted WUP Request ###
        \t AES Encrypted WUP: {self.AES_en_wup}""")
        return self.AES_en_wup


class Attacker():
    def __init__(self, malicious_wup, AES_BITS=128, logger=None) -> None:
        # only kown pubkey, RSA_en_session_key, wup_request.
        self.pk = None
        self.RSA_pak = None
        self.AES_BITS = AES_BITS
        self.pad_wup = AESPad(malicious_wup, self.AES_BITS)
        

    def CCA2(self, server, pk, RSA_en_session_key):
        # receive public key and RSA_en_session_key
        logger.info(f"""\n\n\n ###[ATTAKER]: Attack Initiated. ###
        \t RSA Public Key: \n\t\tn: {pk[0]}\n\t\te:{pk[1]}
        \t RSA Encrypted Session key: {RSA_en_session_key}""")    
        self.pk = pk
        self.RSA_pak = RSA_en_session_key

        cur_key = 0
        # test AES_BITS bits.
        for b in range(self.AES_BITS-1, -1, -1):
            # cur_RSA_pak is session key of b bit. can be caculate by RSA_pak, pubkey and b.
            cur_RSA_pak = self.RSAShift(self.RSA_pak, b)
            # create cur_session_key and cur_AES.
            cur_session_key = self.genAESKey(cur_key, b)
            cur_AES = AES.new(cur_session_key, AES.MODE_ECB)
            # cur_AES encrypt.
            cur_wup_pak = cur_AES.encrypt(self.pad_wup)

            # send sessionkey and wup.
            logger.info("[attacker =>] sending cur_RSA_pak")
            server.getSessionKey(cur_RSA_pak)
            logger.info("[attacker =>] sending cur_wup_pak")
            if (server.getWup(cur_wup_pak) == False):
                logger.info(f"[attacker <=] session key bit {b} is 1")
                cur_key = cur_key + (1 << self.AES_BITS - 1 - b)
            else:
                logger.info(f"""[attacker <=] session key bit {b} is 0
                \t\tcurrent encrypted wup package: {cur_wup_pak}""")
                
        
        # int to bytes.
        session_key = cur_key.to_bytes((cur_key.bit_length() + 7)// 8, byteorder= 'big')
        logger.info(f"""\n\n\n ###[ATTAKER]: Attack Done. ###
        \t Session Key: {session_key}""")   

    # caculate cur_RSA_pak by RSA_pak, pubkey and b.
    def RSAShift(self, pak: bytes, b: int) -> bytes:
        n = self.pk[0]
        e = self.pk[1]
        pak_int = int.from_bytes(pak, byteorder = 'big')

        # c_b = c * (2 ^(b * e) mod n) (mod n)
        pak_b = pak_int * (pow(2, b * e, n)) % n
        return pak_b.to_bytes((pak_b.bit_length() + 7)//8, byteorder = 'big')

    # create 128bit cur_session_key
    def genAESKey(self, key: int, b: int) -> bytes:
        shift_b = key << b

        # only AES_BITS length
        if shift_b.bit_length() > self.AES_BITS:
            return shift_b.to_bytes((shift_b.bit_length() + 7) // 8, byteorder= 'big')[-self.AES_BITS//8: ]
        return shift_b.to_bytes(self.AES_BITS // 8, byteorder= 'big')


if __name__ == "__main__":
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setLevel(logging.DEBUG)

    fileHandler = logging.FileHandler('log.log', mode='w', encoding='UTF-8')
    fileHandler.setLevel(logging.NOTSET)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    consoleHandler.setFormatter(formatter)
    fileHandler.setFormatter(formatter)

    logger.addHandler(consoleHandler)
    logger.addHandler(fileHandler)

    wup_request = """Plaintext is what encryption algorithms, or ciphers, transform an encrypted message into. It is any readable data — including binary files — in a form that can be seen or utilized without the need for a decryption key or decryption device.
    Plaintext would refer to any message, document, file, and the like intended or having been encrypted. Plaintext is the input to a crypto system, with ciphertext being the output. In cryptography, algorithms transform plaintext into ciphertext, and ciphertext into plaintext. These respective processes are called encryption and decryption. The basis for using such a system is to ensure that the data can only be read by its intended recipient.
Securing plaintext stored in a computer file is paramount, as its unsanctioned theft, disclosure, or transmission results in its contents being fully disclosed and thus potentially actionable. If stored, then, the storage media, the device, its components, and all backups must be secured.
It's standard operating procedure encrypt sensitive data before it is stored or transmitted rather than store or communicate it as plaintext. Data owners or custodians have come to accept that the systems inside which plaintext is stored, and the communications channels over which it travels, are insecure. It is therefore better to handle the data itself with care just as the systems themselves are secured.""".encode("utf-8")

    # c-s init
    client = Client(logger=logger)
    server = Server(RSA= RSA(), wup_format = wup_request, logger=logger)
    
    # C-S channel
    pk = server.send_pk()
    RSA_en_session_key = client.receive_RSA_pk(pk)

    # without attack
    server.getSessionKey(RSA_en_session_key)
    AES_en_wup = client.send_wup_request(wup_request)
    flag = server.getWup(AES_en_wup)

    if flag:
        logger.info("====================================\nSuccessfully Connected. Response is True.")

    # CCA2 ATTACK
    attacker = Attacker(wup_request, logger=logger)
    attacker.CCA2(server, pk, RSA_en_session_key)

