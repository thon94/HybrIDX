import base64
import hashlib
from Crypto.Cipher import AES


class PRF():
    def __init__(self, key):
        self.key = key
        self.private_key = hashlib.sha256(self.key.encode()).digest()
        self.block_size = 16
        self.iv = b"1234567812345678"    # Random.new().read(AES.block_size)


    def set_key(self, new_key):
        self.key = new_key


    def __pad(self, raw):
        return raw + (self.block_size - len(raw) % self.block_size) * chr(self.block_size - len(raw) % self.block_size)


    @staticmethod
    def __unpad(raw):
        last_char = raw[len(raw) - 1:]
        bytes_to_remove = ord(last_char)
        return raw[:-bytes_to_remove]


    def encrypt(self, raw):
        cipher = AES.new(self.private_key, AES.MODE_CBC, self.iv)
        raw = self.__pad(raw)
        return base64.b64encode(self.iv + cipher.encrypt(raw.encode())).decode("utf-8")
    

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        cipher = AES.new(self.private_key, AES.MODE_CBC, self.iv)
        raw = cipher.decrypt(enc[self.block_size:]).decode("utf-8")
        return self.__unpad(raw)
    
    
    def encrypt_gamma(self, enc_gamma):
        bin_str = []
        for char in enc_gamma:
            ascii_val = ord(char)
            binary_val = '{0:08b}'.format(ascii_val)
            bin_str.append(binary_val)
        return ''.join(bin_str)