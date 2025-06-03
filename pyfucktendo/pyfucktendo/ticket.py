from enum import Enum
from io import BytesIO

import binascii

from Crypto.Cipher import AES

class SignatureType(Enum):
    RSA_4096_SHA_1   = 0x10000
    RSA_2048_SHA_1   = 0x10001
    ECDSA_SHA_1      = 0x10002
    RSA_4096_SHA_256 = 0x10003
    RSA_2048_SHA_256 = 0x10004
    ECDSA_SHA_256    = 0x10005
    HMAC_SHA_1_160   = 0x10006

class AbstractTicket:
    def __init__(self):
        self.__signature_type: SignatureType = SignatureType.RSA_4096_SHA_1
        self.__signature: bytes = b""
        self.__signature_issuer: str = ""

    def __i_need_a_function_name(self, signature_type: SignatureType) -> tuple[int, int]:
        match signature_type:
            case SignatureType.RSA_4096_SHA_1 | SignatureType.RSA_4096_SHA_256:
                return 512, 60
            case SignatureType.RSA_2048_SHA_1 | SignatureType.RSA_2048_SHA_256:
                return 256, 60
            case SignatureType.ECDSA_SHA_1 | SignatureType.ECDSA_SHA_256:
                return 60, 64
            case SignatureType.HMAC_SHA_1_160:
                return 20, 40

    def load(self, ticket: bytes):
        data = BytesIO(ticket)
        self.__signature_type = SignatureType(int.from_bytes(data.read(4), "big"))
        signature_size, padding = self.__i_need_a_function_name(self.__signature_type)
        self.__signature = data.read(signature_size)
        data.read(padding)

    def get_signature(self) -> tuple[SignatureType, bytes]:
        return self.__signature_type, self.__signature

    def get_signature_issuer(self) -> str:
        return self.__signature_issuer

class LegacyTicket(AbstractTicket):
    def __init__(self):
        super().__init__()
        self.encrypted_title_key: bytes = b""
        self.title_id: str = ""

    def load(self, ticket: bytes):
        super().load(ticket)
        self.encrypted_title_key = ticket[0x1BF:0x1CF]
        self.title_id = binascii.hexlify(ticket[0x1DC:0x1E4]).decode("utf-8")

    def decrypt_title_key(self, common_key: bytes) -> bytes:
        cipher = AES.new(common_key, AES.MODE_CBC, binascii.unhexlify(self.title_id) + b"\x00" * 8)
        return cipher.decrypt(self.encrypted_title_key)
